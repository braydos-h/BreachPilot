"""0.69 beta release gate (#80). The gate must be honest, not green."""

from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
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
        mod.check_sandbox_fail_closed,
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
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "cli_args.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text("from tools.cli_args import __version__\n", encoding="utf-8")
    (tmp_path / "webui").mkdir()
    (tmp_path / "webui" / "package.json").write_text('{"version": "0.0.1"}', encoding="utf-8")
    result = mod.check_versions(tmp_path)
    assert result.passed is False


def test_version_gate_follows_canonical_cli_version_and_main_reexport(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.68.4"\n', encoding="utf-8")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "cli_args.py").write_text('__version__ = "0.68.4"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text("from tools.cli_args import __version__\n", encoding="utf-8")
    (tmp_path / "webui").mkdir()
    (tmp_path / "webui" / "package.json").write_text('{"version": "0.68.4"}', encoding="utf-8")

    result = mod.check_versions(tmp_path)

    assert result.passed is True, result.detail


def _make_safety_root(tmp_path: Path, doc_text: str) -> Path:
    """Minimal repo layout for check_safety_defaults: schema config + generated docs + one probe."""
    import shutil

    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "generated").mkdir(exist_ok=True)
    shutil.copy(REPO / "config.yaml", tmp_path / "config.yaml")
    shutil.copy(
        REPO / "docs" / "generated" / "safety-defaults.md", tmp_path / "docs" / "generated" / "safety-defaults.md"
    )
    (tmp_path / "README.md").write_text("safe readme\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("safe claude\n", encoding="utf-8")
    (tmp_path / "docs" / "probe.md").write_text(doc_text, encoding="utf-8")
    return tmp_path


def test_safety_defaults_rejects_disabled_host_execution_opt_out(tmp_path):
    mod = _load()
    root = _make_safety_root(
        tmp_path, "`sandbox.enabled: false` is the explicit opt-out for legacy uncontained host execution.\n"
    )
    result = mod.check_safety_defaults(root)
    assert result.passed is False, f"host execution opt-out claim must fail: {result.detail}"
    assert "probe.md" in result.detail


def test_safety_defaults_rejects_native_fallback_opt_in(tmp_path):
    mod = _load()
    root = _make_safety_root(
        tmp_path,
        "`sandbox.fallback_native: true` is an explicit opt-in; when Docker is down this degrades to native execution.\n",
    )
    result = mod.check_safety_defaults(root)
    assert result.passed is False, f"native fallback opt-in claim must fail: {result.detail}"


def test_safety_defaults_allows_rejection_of_legacy_values(tmp_path):
    mod = _load()
    root = _make_safety_root(
        tmp_path,
        "`sandbox.enabled: false` and `sandbox.fallback_native: true` are rejected; "
        "sandbox failures block execution and never fall back to host execution.\n",
    )
    result = mod.check_safety_defaults(root)
    assert result.passed, f"accurate fail-closed wording must pass: {result.detail}"


def test_safety_defaults_generated_table_exists():
    assert (REPO / "docs" / "generated" / "safety-defaults.md").exists()
    text = (REPO / "docs" / "generated" / "safety-defaults.md").read_text(encoding="utf-8")
    assert "fallback_native" in text
    assert "true` are rejected" in text
    assert "compatibility key" in text


def _valid_provenance(trials: int = 5) -> dict:
    return {
        "model_alias": "glm",
        "provider": "ollama",
        "model_id": "glm-5.2:cloud",
        "model_version": "test",
        "temperature": "0.1",
        "scenario_version": "abc123",
        "code_revision": "a" * 40,
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


def _valid_eval_report(trials: int = 5, *, timestamp: str | None = None, outcome: str = "PASS") -> dict:
    return {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "live_outcome": outcome,
        "provenance": _valid_provenance(trials=trials),
    }


def _valid_benchmark_run() -> tuple[dict, dict]:
    scenario_ids = ["scenario-a", "scenario-b"]
    trials = [
        {"scenario_id": scenario_id, "trial_index": index, "status": "VERIFIED"}
        for scenario_id in scenario_ids
        for index in range(5)
    ]
    run = {
        "run_id": "repeat-run",
        "status": "completed",
        "config": {"trials": 5},
        "environment": {
            "sandbox_enabled": True,
            "sandbox_required": True,
            "git_sha": "b" * 40,
            "git_dirty": False,
        },
        "scenario_ids": scenario_ids,
        "trials": trials,
    }
    summary = {
        "trials_total": len(trials),
        "trials_completed": len(trials),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return run, summary


def _valid_main_ruleset() -> dict:
    import json

    return json.loads((REPO / "docs" / "governance" / "ruleset-main.json").read_text(encoding="utf-8"))


def test_external_missing_evidence_stays_external(tmp_path):
    mod = _load()
    results = {r.name: r for r in mod.check_external(tmp_path)}
    for name in ("live-eval-backend", "repeated-trials", "branch-rules-applied", "sandbox-image-published"):
        assert results[name].external, f"{name} must be EXTERNAL when evidence missing"


def test_external_valid_evidence_passes(tmp_path):
    import json

    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_run = eval_dir / "run-1"
    eval_run.mkdir(parents=True)
    (eval_run / "report.json").write_text(json.dumps(_valid_eval_report(trials=5)), encoding="utf-8")
    benchmark_dir = tmp_path / "benchmarks"
    benchmark_run_dir = benchmark_dir / "xben" / "repeat-run"
    benchmark_run_dir.mkdir(parents=True)
    run, summary = _valid_benchmark_run()
    (benchmark_run_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (benchmark_run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    digest = tmp_path / "digests.txt"
    digest.write_text(
        "# Sandbox image digests (nightly)\n"
        f"- created_at: {datetime.now(timezone.utc).isoformat()}\n"
        "- source_revision: " + "c" * 40 + "\n"
        "- base: `ghcr.io/example/breachpilot-sandbox@sha256:" + "a" * 64 + "`\n"
        "- browser: `ghcr.io/example/breachpilot-sandbox@sha256:" + "b" * 64 + "`\n",
        encoding="utf-8",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([_valid_main_ruleset()]), encoding="utf-8")
    results = {
        r.name: r
        for r in mod.check_external(
            tmp_path,
            eval_dir=eval_dir,
            benchmark_dir=benchmark_dir,
            sandbox_digest_file=digest,
            branch_rules_file=rules,
        )
    }
    assert results["live-eval-backend"].passed and not results["live-eval-backend"].external
    assert results["repeated-trials"].passed and not results["repeated-trials"].external
    assert results["branch-rules-applied"].passed
    assert results["sandbox-image-published"].passed


def test_external_stale_evidence_fails(tmp_path):
    import json

    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    bad = _valid_eval_report()
    del bad["provenance"]["config_hash"]
    bad_dir = eval_dir / "bad"
    bad_dir.mkdir()
    (bad_dir / "report.json").write_text(json.dumps(bad), encoding="utf-8")
    invalid = mod._verify_eval_dir(eval_dir)
    assert invalid.passed is False and invalid.external is False
    stale_dir = tmp_path / "stale-eval"
    stale_dir.mkdir()
    stale = datetime.now(timezone.utc) - timedelta(days=100)
    (stale_dir / "report.json").write_text(
        json.dumps(_valid_eval_report(timestamp=stale.isoformat())), encoding="utf-8"
    )
    stale_result = mod._verify_eval_dir(stale_dir)
    assert stale_result.passed is False and stale_result.external is False
    # Malformed digest fails.
    digest = tmp_path / "digests.txt"
    digest.write_text(
        "- created_at: 2026-09-15T00:00:00Z\n"
        "- source_revision: " + "c" * 40 + "\n"
        "- base: ghcr.io/example/breachpilot-sandbox@sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    assert mod._verify_sandbox_digest(digest).passed is False
    # Ruleset without main fails.
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"name": "other", "enforcement": "active"}]), encoding="utf-8")
    assert mod._verify_branch_rules(rules).passed is False


def test_skipped_eval_is_not_live_backend_evidence(tmp_path):
    import json

    mod = _load()
    (tmp_path / "report.json").write_text(json.dumps(_valid_eval_report(outcome="SKIPPED")), encoding="utf-8")
    result = mod._verify_eval_dir(tmp_path)
    assert not result.passed and not result.external


def test_repeated_trial_gate_requires_persisted_trials_per_scenario(tmp_path):
    import json

    mod = _load()
    run, summary = _valid_benchmark_run()
    run["trials"] = run["trials"][:4]
    summary["trials_total"] = 4
    summary["trials_completed"] = 4
    run_dir = tmp_path / "xben" / "short-run"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    result = mod._verify_benchmark_trials(tmp_path)
    assert not result.passed and not result.external


def test_branch_rules_require_the_documented_main_protections(tmp_path):
    import json

    mod = _load()
    path = tmp_path / "rules.json"
    base = _valid_main_ruleset()
    path.write_text(json.dumps([base]), encoding="utf-8")
    assert mod._verify_branch_rules(path).passed

    decoys = [
        {**base, "enforcement": "evaluate"},
        {**base, "conditions": {"ref_name": {"include": ["refs/heads/main-copy"], "exclude": []}}},
        {**base, "conditions": {"ref_name": {"include": ["refs/heads/release/main"], "exclude": []}}},
        {**base, "bypass_actors": [{"actor_id": 1, "actor_type": "Team", "bypass_mode": "always"}]},
        {**base, "rules": [rule for rule in base["rules"] if rule["type"] != "non_fast_forward"]},
        {
            **base,
            "rules": [
                {
                    **rule,
                    "parameters": {**rule["parameters"], "strict_required_status_checks_policy": False},
                }
                if rule["type"] == "required_status_checks"
                else rule
                for rule in base["rules"]
            ],
        },
        {
            **base,
            "rules": [
                {
                    **rule,
                    "parameters": {
                        **rule["parameters"],
                        "required_status_checks": [
                            check
                            for check in rule["parameters"]["required_status_checks"]
                            if check["context"] != "Analyze (javascript)"
                        ],
                    },
                }
                if rule["type"] == "required_status_checks"
                else rule
                for rule in base["rules"]
            ],
        },
        {
            **base,
            "rules": [
                {
                    **rule,
                    "parameters": {**rule["parameters"], "required_approving_review_count": 0},
                }
                if rule["type"] == "pull_request"
                else rule
                for rule in base["rules"]
            ],
        },
        {**base, "rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": []}}]},
    ]
    for decoy in decoys:
        path.write_text(json.dumps([decoy]), encoding="utf-8")
        result = mod._verify_branch_rules(path)
        assert not result.passed, f"incomplete or weakened ruleset passed: {decoy}"


def test_sandbox_digest_requires_full_sha256(tmp_path):
    mod = _load()
    path = tmp_path / "digest.txt"
    for malformed in ("sha256:" + "a" * 32, "sha256:" + "g" * 64, "sha256:" + "a" * 65):
        path.write_text(malformed, encoding="utf-8")
        assert not mod._verify_sandbox_digest(path).passed
    path.write_text("ghcr.io/example/worker@sha256:" + "a" * 64, encoding="utf-8")
    assert not mod._verify_sandbox_digest(path).passed


def test_release_evidence_requires_exact_full_source_revision(tmp_path):
    import json

    mod = _load()
    expected = "a" * 40
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    report = _valid_eval_report()
    (eval_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    assert mod._verify_eval_dir(eval_dir, expected_revision=expected).passed

    for invalid_revision in (expected[:7], expected + "0", "b" * 40, "unknown"):
        report["provenance"]["code_revision"] = invalid_revision
        (eval_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        assert not mod._verify_eval_dir(eval_dir, expected_revision=expected).passed, invalid_revision

    benchmark_dir = tmp_path / "benchmarks"
    benchmark_run_dir = benchmark_dir / "xben" / "run-1"
    benchmark_run_dir.mkdir(parents=True)
    run, summary = _valid_benchmark_run()
    run["environment"]["git_sha"] = expected
    (benchmark_run_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (benchmark_run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    assert mod._verify_benchmark_trials(benchmark_dir, expected_revision=expected).passed
    for invalid_revision in (expected[:7], expected + "0", "b" * 40):
        run["environment"]["git_sha"] = invalid_revision
        (benchmark_run_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
        assert not mod._verify_benchmark_trials(benchmark_dir, expected_revision=expected).passed, invalid_revision

    digest = tmp_path / "digests.md"
    digest.write_text(
        f"- created_at: {datetime.now(timezone.utc).isoformat()}\n"
        f"- source_revision: {expected}\n"
        "- base: ghcr.io/example/breachpilot-sandbox@sha256:" + "a" * 64 + "\n"
        "- browser: ghcr.io/example/breachpilot-sandbox@sha256:" + "b" * 64 + "\n",
        encoding="utf-8",
    )
    assert mod._verify_sandbox_digest(digest, expected_revision=expected).passed
    digest.write_text(digest.read_text(encoding="utf-8").replace(expected, "c" * 40), encoding="utf-8")
    assert not mod._verify_sandbox_digest(digest, expected_revision=expected).passed


def test_no_unconditional_external_without_verification():
    import inspect

    mod = _load()
    src = inspect.getsource(mod.check_external)
    assert "eval_dir" in src and "sandbox_digest" in src and "branch_rules" in src
    assert "_external(" in src  # safe default preserved
    assert "_verify_eval_dir" in src
