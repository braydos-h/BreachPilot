#!/usr/bin/env python3
"""0.69 beta release gate (#80): executable form of the beta-means-beta contract.

Every box that can be checked locally is checked here; boxes needing live
infrastructure or maintainer action are reported as EXTERNAL (never green).
Exit 0 + ``GO`` only when all local boxes pass AND no EXTERNAL box is
claimed satisfied. CI ``release.yml`` runs this before publishing assets.

Usage: ``python scripts/release_gate.py [--root DIR]``
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch


@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str = ""
    external: bool = False


@dataclass
class GateReport:
    results: list[GateResult] = field(default_factory=list)

    @property
    def failures(self) -> list[GateResult]:
        return [r for r in self.results if not r.passed and not r.external]

    @property
    def externals(self) -> list[GateResult]:
        return [r for r in self.results if r.external]

    @property
    def verdict(self) -> str:
        return "GO" if not self.failures and not self.externals else "NO-GO"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "results": [
                {"name": r.name, "passed": r.passed, "external": r.external, "detail": r.detail} for r in self.results
            ],
        }


def _ok(name: str, detail: str = "") -> GateResult:
    return GateResult(name, True, detail)


def _fail(name: str, detail: str = "") -> GateResult:
    return GateResult(name, False, detail)


def _external(name: str, detail: str = "") -> GateResult:
    return GateResult(name, False, detail, external=True)


def check_versions(root: Path) -> GateResult:
    """pyproject == tools.cli_args.__version__ == main re-export == webui."""
    import tomllib

    try:
        py = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        py_version = str(py["project"]["version"]).strip()
        cli_text = (root / "tools" / "cli_args.py").read_text(encoding="utf-8")
        cli_match = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", cli_text)
        cli_version = cli_match.group(1).strip() if cli_match else ""
        main_text = (root / "main.py").read_text(encoding="utf-8")
        imports_cli_version = any(
            any(token.strip() == "__version__" for token in match.group(1).split(","))
            for match in re.finditer(r"from\s+tools\.cli_args\s+import\s+([^\n]+)", main_text)
        )
        main_version = cli_version if imports_cli_version else ""
        webui = json.loads((root / "webui" / "package.json").read_text(encoding="utf-8"))
        web_version = str(webui["version"]).strip()
    except (OSError, KeyError, ValueError) as exc:
        return _fail("versions-consistent", f"cannot read versions: {exc}")
    if len({py_version, cli_version, main_version, web_version}) == 1:
        return _ok("versions-consistent", f"all report {py_version}")
    return _fail(
        "versions-consistent",
        "mismatch: "
        f"pyproject={py_version!r} tools/cli_args={cli_version!r} "
        f"main-re-export={main_version!r} webui={web_version!r}",
    )


def check_ci_tiers(root: Path) -> GateResult:
    """Required CI tiers and an exact-SHA release gate are wired."""
    import yaml

    try:
        ci_jobs = set(
            (yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8")) or {}).get("jobs", {})
        )
        eval_jobs = set(
            (yaml.safe_load((root / ".github/workflows/eval.yml").read_text(encoding="utf-8")) or {}).get("jobs", {})
        )
        release = yaml.safe_load((root / ".github/workflows/release.yml").read_text(encoding="utf-8")) or {}
    except OSError as exc:
        return _fail("ci-tiers", f"cannot read workflows: {exc}")
    missing = {"tests", "lint", "types", "package", "webui", "audit", "sandbox", "browser"} - ci_jobs
    if missing:
        return _fail("ci-tiers", f"ci.yml missing jobs: {sorted(missing)}")
    if "eval-unit" not in eval_jobs or "nightly-eval" not in eval_jobs:
        return _fail("ci-tiers", "eval.yml missing eval-unit/nightly-eval")
    release_jobs = release.get("jobs", {})
    gate_steps = release_jobs.get("gate", {}).get("steps", []) if isinstance(release_jobs, dict) else []
    source_guard = next(
        (
            step
            for step in gate_steps
            if isinstance(step, dict) and step.get("name") == "Require main ancestry and CI success for release SHA"
        ),
        None,
    )
    guard_script = source_guard.get("run", "") if isinstance(source_guard, dict) else ""
    required_guard_tokens = (
        'git merge-base --is-ancestor "$GITHUB_SHA" FETCH_HEAD',
        "commits/$GITHUB_SHA/check-runs",
        'check.get("name") == "CI success"',
        'check.get("conclusion") == "success"',
    )
    if not all(token in guard_script for token in required_guard_tokens):
        return _fail(
            "release-source-guard", "release gate does not require main ancestry and CI success for its exact SHA"
        )
    build_needs = release_jobs.get("build", {}).get("needs", []) if isinstance(release_jobs, dict) else []
    if "gate" not in (build_needs if isinstance(build_needs, list) else [build_needs]):
        return _fail("release-source-guard", "release build does not depend on the gated job")
    return _ok("ci-tiers", "Tier 1/2 + eval-unit + nightly-eval present")


def check_eval_skip_visibility(root: Path) -> GateResult:
    """Missing live infra must produce SKIPPED, never silent green."""
    text = (root / ".github/workflows/eval.yml").read_text(encoding="utf-8")
    if "write_skipped_eval_report" in text and "SKIPPED" in text:
        return _ok("eval-skip-visible", "nightly-eval writes an explicit SKIPPED report")
    return _fail("eval-skip-visible", "eval.yml has no SKIPPED-report step")


def check_safety_defaults(root: Path) -> GateResult:
    """Schema + shipped config + docs agree on fail-closed sandbox defaults."""
    sys.path.insert(0, str(root))
    try:
        from tools.config_manager import CONFIG_SCHEMA

        sandbox = CONFIG_SCHEMA["sandbox"]
        if sandbox.get("enabled") is not True or sandbox.get("fallback_native") is not False:
            return _fail("safety-defaults", f"schema sandbox defaults drifted: {sandbox}")
        import yaml

        cfg = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))
        for key in ("enabled", "fallback_native"):
            if cfg["sandbox"][key] != sandbox[key]:
                return _fail("safety-defaults", f"config.yaml sandbox.{key} drifts from schema")
    except (OSError, KeyError) as exc:
        return _fail("safety-defaults", f"cannot verify: {exc}")
    finally:
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    bad = []
    # Reject claims that enable a host/native mode. Mentioning rejected legacy
    # values in a fail-closed explanation is valid, so match the unsafe action
    # (opt-out/degrade) rather than the setting names alone.
    stale_patterns = [
        r"sandbox\.enabled\s*:\s*false[^\n]{0,40}(?:is|means|allows?|=)[^\n]{0,60}(?:opt[- ]out|host execution|native mode|uncontained)",
        r"fallback_native\s*:?\s*`?true`?[^\n]{0,160}(?:explicit opt[- ]in|degrad(?:e|es|ed)|runs? natively|native execution)",
        r"fallback_native[^\n]{0,120}(?:explicit opt[- ]in|degrad(?:e|es|ed))[^\n]{0,100}(?:host|native)",
        r"sandbox disabled[^\n]{0,100}(?:commands? (?:run|execute)|host execution|native mode)",
    ]
    for path in [root / "README.md", root / "CLAUDE.md", *(root / "docs").rglob("*.md")]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if any(re.search(pat, text, re.IGNORECASE) for pat in stale_patterns):
            bad.append(str(path.relative_to(root)))
    if bad:
        return _fail("safety-defaults", f"unsafe sandbox host/native fallback claims in: {bad}")
    generated = root / "docs" / "generated" / "safety-defaults.md"
    try:
        generated_text = generated.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("safety-defaults", f"generated safety defaults missing: {exc}")
    if "sandbox.enabled: false` and `fallback_native: true` are rejected" not in generated_text:
        return _fail("safety-defaults", "generated safety defaults do not state that unsafe opt-outs are rejected")
    return _ok("safety-defaults", "schema + config.yaml + docs agree (sandbox unavailable blocks execution)")


def check_safety_suite(root: Path) -> GateResult:
    """Red-team suite collects the expected number of tests."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_safety_redteam.py",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-n",
            "0",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(root),
    )
    match = re.search(r"(\d+)\s+test", (proc.stdout + proc.stderr).replace("tests", "test"))
    count = int(match.group(1)) if match else 0
    if proc.returncode != 0 or count < 23:
        return _fail("safety-suite", f"expected >=23 red-team tests, collected {count}")
    return _ok("safety-suite", f"safety regression: {count}/{count} collected")


def check_negative_controls(root: Path) -> GateResult:
    """Secure + impossible oracles exist and score correctly."""
    sys.path.insert(0, str(root))
    try:
        from tools.eval_harness import score_against_oracle

        for name in ("secure_web.oracle.json", "impossible_sqli.oracle.json"):
            oracle = json.loads((root / "eval_targets" / name).read_text(encoding="utf-8"))
            if not oracle.get("negative_control"):
                return _fail("negative-controls", f"{name} missing negative_control flag")
            if not score_against_oracle([], oracle).success:
                return _fail("negative-controls", f"{name}: empty claim set does not score success")
            claimed = score_against_oracle([{"type": "vulnerability", "value": "sqli"}], oracle)
            if claimed.success or claimed.false_positives != 1:
                return _fail("negative-controls", f"{name}: decoy claim is not a false positive")
    except (OSError, KeyError, ValueError) as exc:
        return _fail("negative-controls", f"cannot verify: {exc}")
    finally:
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    return _ok("negative-controls", "secure_web + impossible_sqli score REFUTED correctly")


def check_provenance_fields(root: Path) -> GateResult:
    """Eval provenance pins model/prompt/catalog/sandbox identity."""
    sys.path.insert(0, str(root))
    try:
        from tools.eval_harness import RunProvenance, write_skipped_eval_report  # noqa: F401

        required = {
            "model_alias",
            "provider",
            "model_id",
            "model_version",
            "temperature",
            "scenario_version",
            "code_revision",
            "breachpilot_version",
            "config_hash",
            "prompt_hash",
            "tool_catalog_hash",
            "skill_catalog_hash",
            "sandbox_image",
            "sandbox_image_digest",
            "orchestration_mode",
            "provider_adapter_version",
        }
        missing = required - set(RunProvenance.__dataclass_fields__)
        if missing:
            return _fail("provenance", f"RunProvenance missing fields: {sorted(missing)}")
    except ImportError as exc:
        return _fail("provenance", f"cannot import: {exc}")
    finally:
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    return _ok("provenance", "model/prompt/catalog/sandbox identity pinned")


def check_sandbox_fail_closed(root: Path) -> GateResult:
    """Unsafe sandbox opt-outs are rejected and missing Docker cannot select host execution."""
    sys.path.insert(0, str(root))
    try:
        from tools.sandbox.docker_lifecycle import DockerLifecycle
        from tools.sandbox.manager import resolve_manager_with_fallback
        from tools.sandbox.models import SandboxConfig

        for sandbox in ({"enabled": False}, {"enabled": True, "fallback_native": True}):
            try:
                SandboxConfig.from_config({"sandbox": sandbox})
            except ValueError:
                continue
            return _fail("sandbox-fail-closed", f"unsafe config was accepted: {sandbox}")

        class UnavailableDocker:
            def acquire(self) -> tuple[bool, str]:
                return False, "daemon unavailable"

        with tempfile.TemporaryDirectory(prefix="bp-release-sandbox-") as workspace:
            config = {"sandbox": {"enabled": True, "fallback_native": False}, "exploit": {"workspace_dir": workspace}}
            with (
                patch.object(DockerLifecycle, "from_config", return_value=UnavailableDocker()),
                patch("tools.sandbox.manager._record_boot_state"),
            ):
                manager, notice = resolve_manager_with_fallback(Path(workspace), config)
            if manager is None or notice:
                return _fail("sandbox-fail-closed", "unavailable Docker selected a non-sandbox execution path")
    except (ImportError, AttributeError, OSError, TypeError, ValueError) as exc:
        return _fail("sandbox-fail-closed", f"cannot verify fail-closed sandbox behavior: {exc}")
    finally:
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    return _ok("sandbox-fail-closed", "unsafe opt-outs rejected; unavailable Docker retains a sandbox manager")


def check_docs_contract(root: Path) -> GateResult:
    """Release-relevant docs exist: reliability, pyramid, branch protection, release."""
    missing = [
        str(p)
        for p in (
            "docs/reliability-metrics.md",
            "docs/ci-pyramid.md",
            "docs/branch-protection.md",
            "docs/release.md",
            "SECURITY.md",
        )
        if not (root / p).exists()
    ]
    if missing:
        return _fail("docs-contract", f"missing docs: {missing}")
    return _ok("docs-contract", "reliability + pyramid + branch-protection + release + SECURITY present")


def check_js_scan(root: Path) -> GateResult:
    """npm audit gate present in CI (parity with pip-audit); missing/soft scan fails."""
    try:
        text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("js-scan", f"cannot read ci.yml: {exc}")
    if "npm audit" not in text:
        return _fail("js-scan", "ci.yml has no npm audit step (JS vuln gate missing)")
    return _ok("js-scan", "npm audit gate present in CI audit job")


def _required_provenance_fields() -> set[str]:
    return {
        "model_alias",
        "provider",
        "model_id",
        "model_version",
        "temperature",
        "scenario_version",
        "code_revision",
        "breachpilot_version",
        "config_hash",
        "prompt_hash",
        "tool_catalog_hash",
        "skill_catalog_hash",
        "sandbox_image",
        "sandbox_image_digest",
        "orchestration_mode",
        "provider_adapter_version",
    }


def _verify_eval_dir(eval_dir: Path | None, *, expected_revision: str = "") -> GateResult:
    """Verify live-eval evidence from an artifacts dir.

    A valid report must be an executed PASS/FAIL report with complete
    provenance. SKIPPED and INFRA_ERROR reports do not prove that the live
    backend ran. Repeated-trial evidence is checked separately from actual
    benchmark run/trial records; eval target count is not a repeat count.
    """
    if eval_dir is None:
        return _external(
            "live-eval-backend",
            "no model backend report supplied (or pass --eval-dir with executed provenance reports)",
        )
    try:
        files = sorted(eval_dir.rglob("report.json"))
    except OSError as exc:
        return _fail("live-eval-backend", f"cannot read --eval-dir: {exc}")
    if not files:
        return _external("live-eval-backend", f"--eval-dir {eval_dir} has no report.json artifacts")

    required = _required_provenance_fields()
    valid: list[dict] = []
    errors: list[str] = []
    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: unreadable ({exc})")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path.name}: report is not an object")
            continue
        prov = payload.get("provenance")
        if payload.get("live_outcome") not in {"PASS", "FAIL"}:
            errors.append(f"{path.name}: live_outcome is not an executed PASS/FAIL")
            continue
        if not isinstance(prov, dict):
            errors.append(f"{path.name}: provenance not an object")
            continue
        missing = required - set(prov.keys())
        if missing:
            errors.append(f"{path.name}: missing provenance fields {sorted(missing)}")
            continue
        report_revision = str(prov.get("code_revision", "") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{40}", report_revision):
            errors.append(f"{path.name}: code_revision must be a full 40-character commit SHA")
            continue
        if expected_revision and report_revision != expected_revision.lower():
            errors.append(f"{path.name}: code_revision does not exactly match the release checkout")
            continue
        # Check the report's recorded time. Artifact download resets local
        # mtimes, so filesystem freshness would make old evidence look new.
        timestamp = payload.get("timestamp")
        try:
            from datetime import datetime, timezone

            reported_at = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - reported_at.astimezone(timezone.utc)).total_seconds() / 86400
        except (TypeError, ValueError):
            errors.append(f"{path.name}: missing or invalid report timestamp")
            continue
        if age_days < -1 or age_days > 90:
            errors.append(f"{path.name}: stale or future-dated report ({age_days:.0f}d, max age 90d)")
            continue
        valid.append({"path": path.name, "provenance": prov})
    if not valid:
        return _fail("live-eval-backend", f"no valid provenance in --eval-dir: {'; '.join(errors[:3])}")
    return _ok("live-eval-backend", f"{len(valid)} executed provenance report(s) in {eval_dir}")


def _verify_benchmark_trials(benchmark_dir: Path | None, *, expected_revision: str = "") -> GateResult:
    """Require five persisted trial results for every scenario in a completed run."""
    if benchmark_dir is None:
        return _external("repeated-trials", "no benchmark trial records supplied (pass --benchmark-dir)")
    try:
        run_files = sorted(benchmark_dir.rglob("run.json"))
    except OSError as exc:
        return _fail("repeated-trials", f"cannot read --benchmark-dir: {exc}")
    if not run_files:
        return _external("repeated-trials", f"--benchmark-dir {benchmark_dir} has no run.json records")

    errors: list[str] = []
    for run_path in run_files:
        try:
            run = json.loads(run_path.read_text(encoding="utf-8"))
            summary = json.loads((run_path.parent / "summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{run_path.parent.name}: incomplete or invalid run/summary ({exc})")
            continue
        if not isinstance(run, dict) or not isinstance(summary, dict):
            errors.append(f"{run_path.parent.name}: run and summary must be objects")
            continue
        config = run.get("config")
        env = run.get("environment")
        scenario_ids = run.get("scenario_ids")
        trials = run.get("trials")
        if run.get("status") != "completed" or not isinstance(config, dict) or config.get("trials", 0) < 5:
            errors.append(f"{run_path.parent.name}: run is not completed with a configured trial count >=5")
            continue
        if (
            not isinstance(env, dict)
            or env.get("sandbox_enabled") is not True
            or env.get("sandbox_required") is not True
        ):
            errors.append(f"{run_path.parent.name}: benchmark environment does not prove required sandbox execution")
            continue
        benchmark_revision = str(env.get("git_sha", "") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{40}", benchmark_revision) or env.get("git_dirty") is not False:
            errors.append(f"{run_path.parent.name}: benchmark source revision is not a full SHA or tree is dirty")
            continue
        if expected_revision and benchmark_revision != expected_revision.lower():
            errors.append(f"{run_path.parent.name}: benchmark git_sha does not exactly match the release checkout")
            continue
        if not isinstance(scenario_ids, list) or not scenario_ids or not isinstance(trials, list):
            errors.append(f"{run_path.parent.name}: scenario IDs or persisted trial records are missing")
            continue
        if summary.get("trials_total") != len(trials) or summary.get("trials_completed", 0) < 5:
            errors.append(f"{run_path.parent.name}: summary does not match persisted trial records")
            continue
        try:
            from datetime import datetime, timezone

            summary_time = datetime.fromisoformat(str(summary["timestamp"]).replace("Z", "+00:00"))
            if summary_time.tzinfo is None:
                summary_time = summary_time.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - summary_time.astimezone(timezone.utc)).total_seconds() / 86400
        except (KeyError, TypeError, ValueError):
            errors.append(f"{run_path.parent.name}: benchmark summary timestamp is missing or invalid")
            continue
        if age_days < -1 or age_days > 90:
            errors.append(f"{run_path.parent.name}: benchmark evidence stale or future-dated ({age_days:.0f}d)")
            continue
        counts: dict[str, set[int]] = {str(scenario_id): set() for scenario_id in scenario_ids}
        for trial in trials:
            if not isinstance(trial, dict):
                continue
            scenario_id = str(trial.get("scenario_id", ""))
            index = trial.get("trial_index")
            status = trial.get("status")
            if (
                scenario_id in counts
                and isinstance(index, int)
                and index >= 0
                and status in {"VERIFIED", "FAILED", "FALSE_POSITIVE", "TIMEOUT"}
            ):
                counts[scenario_id].add(index)
        if all(len(indices) >= 5 for indices in counts.values()):
            return _ok(
                "repeated-trials",
                f"completed sandboxed benchmark {run.get('run_id', run_path.parent.name)} has five persisted trials per scenario",
            )
        errors.append(f"{run_path.parent.name}: fewer than five persisted trials for at least one scenario")
    return _fail("repeated-trials", "; ".join(errors[:3]) or "no repeated benchmark run passed verification")


def _verify_branch_rules(path: Path | None) -> GateResult:
    """Verify the complete documented main ruleset against GitHub API JSON.

    The repo's ``docs/governance/ruleset-main.json`` is the contract. A
    partial ruleset that merely names ``main`` and requires CI is insufficient:
    the release gate also requires the documented review, status, and bypass
    protections. Missing evidence is EXTERNAL; present-but-wrong evidence FAILs.
    """
    if path is None:
        return _external(
            "branch-rules-applied", "ruleset must be applied by a repo admin; see docs/branch-protection.md"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _fail("branch-rules-applied", f"cannot read --branch-rules-file: {exc}")
    rulesets = payload if isinstance(payload, list) else [payload]
    if not rulesets or not all(isinstance(item, dict) for item in rulesets):
        return _fail("branch-rules-applied", "branch-rules file has no rulesets")

    spec_path = Path(__file__).resolve().parent.parent / "docs" / "governance" / "ruleset-main.json"
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _fail("branch-rules-applied", f"cannot read documented ruleset contract: {exc}")
    spec_conditions = spec.get("conditions", {})
    spec_ref_name = spec_conditions.get("ref_name", {}) if isinstance(spec_conditions, dict) else {}
    spec_rules = spec.get("rules", [])
    if not isinstance(spec_rules, list) or not isinstance(spec_ref_name, dict):
        return _fail("branch-rules-applied", "documented main ruleset contract is malformed")
    expected_statuses: dict[str, int | None] = {}
    expected_status_rule: dict = {}
    expected_pull_rule: dict = {}
    for rule in spec_rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") == "required_status_checks":
            expected_status_rule = rule
            parameters = rule.get("parameters", {})
            checks = parameters.get("required_status_checks", []) if isinstance(parameters, dict) else []
            if isinstance(checks, list):
                expected_statuses = {
                    str(check["context"]): check.get("integration_id")
                    for check in checks
                    if isinstance(check, dict) and isinstance(check.get("context"), str)
                }
        elif rule.get("type") == "pull_request":
            expected_pull_rule = rule
    if not expected_statuses or not expected_status_rule or not expected_pull_rule:
        return _fail("branch-rules-applied", "documented main ruleset lacks review or status-check requirements")

    def protects_main_as_documented(ruleset: dict) -> bool:
        if ruleset.get("enforcement") != "active" or ruleset.get("target") != "branch":
            return False
        conditions = ruleset.get("conditions")
        if not isinstance(conditions, dict):
            return False
        ref_name = conditions.get("ref_name")
        if not isinstance(ref_name, dict):
            return False
        include = ref_name.get("include")
        exclude = ref_name.get("exclude", [])
        if not isinstance(include, list) or not isinstance(exclude, list):
            return False
        if include != spec_ref_name.get("include") or exclude != spec_ref_name.get("exclude", []):
            return False
        if ruleset.get("bypass_actors", []) != spec.get("bypass_actors", []):
            return False

        rules = ruleset.get("rules")
        if not isinstance(rules, list):
            return False
        by_type = {rule.get("type"): rule for rule in rules if isinstance(rule, dict)}
        expected_types = {rule.get("type") for rule in spec_rules if isinstance(rule, dict)}
        if not expected_types <= set(by_type):
            return False
        if by_type["required_status_checks"].get("parameters") != expected_status_rule.get("parameters"):
            return False
        if by_type["pull_request"].get("parameters") != expected_pull_rule.get("parameters"):
            return False
        actual_status_checks = by_type["required_status_checks"]["parameters"].get("required_status_checks", [])
        actual_statuses = {
            str(check.get("context")): check.get("integration_id")
            for check in actual_status_checks
            if isinstance(check, dict) and isinstance(check.get("context"), str)
        }
        if not expected_statuses.items() <= actual_statuses.items():
            return False
        return True

    if not any(protects_main_as_documented(ruleset) for ruleset in rulesets):
        return _fail(
            "branch-rules-applied",
            "no active main ruleset matches docs/governance/ruleset-main.json review, status, and bypass protections",
        )
    return _ok("branch-rules-applied", f"documented main protections verified from {path.name}")


def _verify_sandbox_digest(path: Path | None, *, expected_revision: str = "") -> GateResult:
    """Verify published sandbox-image digest artifact.

    Contract: ``--sandbox-digest-file`` is ``DIGESTS.md`` from
    sandbox-image.yml and identifies base + browser GHCR digests, source
    revision, and creation time. The workflow separately verifies cosign
    signatures before running the gate.
    """
    if path is None:
        return _external("sandbox-image-published", "prebuilt image not yet pushed to GHCR; see sandbox-image.yml")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("sandbox-image-published", f"cannot read --sandbox-digest-file: {exc}")
    normalized = text.lower()
    base_match = re.search(
        r"(?m)^\s*-\s*base:\s*`?ghcr\.io/[a-z0-9_.-]+/breachpilot-sandbox@sha256:[0-9a-f]{64}`?\s*$",
        normalized,
    )
    browser_match = re.search(
        r"(?m)^\s*-\s*browser:\s*`?ghcr\.io/[a-z0-9_.-]+/breachpilot-sandbox@sha256:[0-9a-f]{64}`?\s*$",
        normalized,
    )
    if not base_match or not browser_match:
        return _fail("sandbox-image-published", f"{path.name} must contain full base and browser GHCR digests")
    revision = re.search(r"(?m)^\s*-\s*source_revision:\s*([0-9a-f]{40})\s*$", normalized)
    created_at = re.search(r"(?m)^\s*-\s*created_at:\s*(\S+)\s*$", text)
    if not revision or not created_at:
        return _fail("sandbox-image-published", f"{path.name} must identify a full source revision and creation time")
    if expected_revision and revision.group(1) != expected_revision.lower():
        return _fail("sandbox-image-published", "sandbox source_revision does not exactly match the release checkout")
    try:
        from datetime import datetime, timezone

        recorded_at = datetime.fromisoformat(created_at.group(1).replace("Z", "+00:00"))
        if recorded_at.tzinfo is None:
            recorded_at = recorded_at.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - recorded_at.astimezone(timezone.utc)).total_seconds() / 86400
    except ValueError:
        return _fail("sandbox-image-published", f"{path.name} has an invalid creation time")
    if age_days < -1 or age_days > 90:
        return _fail("sandbox-image-published", f"{path.name} image evidence stale or future-dated ({age_days:.0f}d)")
    return _ok("sandbox-image-published", f"signed base/browser image digest evidence from {path.name}")


def check_external(
    root: Path,
    *,
    eval_dir: Path | None = None,
    benchmark_dir: Path | None = None,
    sandbox_digest_file: Path | None = None,
    branch_rules_file: Path | None = None,
) -> list[GateResult]:
    """Boxes needing live infra or maintainer action — EXTERNAL unless evidence verifies.

    Each box is satisfiable via an artifact (see docs/release.md):
    executed eval reports, persisted benchmark trials, GHCR digest file,
    branch-rules API output.
    Missing evidence stays EXTERNAL; invalid/stale evidence FAILs.
    """
    _ = root
    expected_revision = ""
    try:
        revision_result = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, cwd=root, check=False
        )
        if revision_result.returncode == 0:
            expected_revision = revision_result.stdout.strip().lower()
    except (OSError, subprocess.SubprocessError):
        pass
    live = _verify_eval_dir(eval_dir, expected_revision=expected_revision)
    repeated = _verify_benchmark_trials(benchmark_dir, expected_revision=expected_revision)
    return [
        live,
        repeated,
        _verify_branch_rules(branch_rules_file),
        _verify_sandbox_digest(sandbox_digest_file, expected_revision=expected_revision),
    ]


def run_gate(
    root: Path,
    *,
    eval_dir: Path | None = None,
    benchmark_dir: Path | None = None,
    sandbox_digest_file: Path | None = None,
    branch_rules_file: Path | None = None,
) -> GateReport:
    report = GateReport()
    report.results += [
        check_versions(root),
        check_ci_tiers(root),
        check_eval_skip_visibility(root),
        check_safety_defaults(root),
        check_safety_suite(root),
        check_negative_controls(root),
        check_provenance_fields(root),
        check_sandbox_fail_closed(root),
        check_docs_contract(root),
        check_js_scan(root),
        *check_external(
            root,
            eval_dir=eval_dir,
            benchmark_dir=benchmark_dir,
            sandbox_digest_file=sandbox_digest_file,
            branch_rules_file=branch_rules_file,
        ),
    ]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="0.69 beta release gate (GO/NO-GO).")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument(
        "--eval-dir",
        default=None,
        help="dir of executed eval JSON reports with provenance (satisfies live-eval-backend)",
    )
    parser.add_argument(
        "--benchmark-dir",
        default=None,
        help="dir of persisted benchmark run/trial records (satisfies repeated-trials)",
    )
    parser.add_argument(
        "--sandbox-digest-file", default=None, help="file containing published sandbox image sha256 digest"
    )
    parser.add_argument(
        "--branch-rules-file", default=None, help="gh api rulesets JSON output (satisfies branch-rules-applied)"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    def _opt(p: str | None) -> Path | None:
        if not p:
            return None
        candidate = Path(p)
        return candidate if candidate.is_absolute() else (root / candidate)

    report = run_gate(
        root,
        eval_dir=_opt(args.eval_dir),
        benchmark_dir=_opt(args.benchmark_dir),
        sandbox_digest_file=_opt(args.sandbox_digest_file),
        branch_rules_file=_opt(args.branch_rules_file),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"release gate: {report.verdict}")
        for result in report.results:
            tag = "EXTERNAL" if result.external else ("ok" if result.passed else "FAIL")
            print(f"  [{tag}] {result.name}: {result.detail or ('pass' if result.passed else 'fail')}")
    return 0 if report.verdict == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
