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
from dataclasses import dataclass, field
from pathlib import Path


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
    """pyproject == main.__version__ == webui/package.json."""
    import tomllib

    try:
        py = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        py_version = str(py["project"]["version"]).strip()
        main_text = (root / "main.py").read_text(encoding="utf-8")
        match = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", main_text)
        main_version = match.group(1).strip() if match else ""
        webui = json.loads((root / "webui" / "package.json").read_text(encoding="utf-8"))
        web_version = str(webui["version"]).strip()
    except (OSError, KeyError, ValueError) as exc:
        return _fail("versions-consistent", f"cannot read versions: {exc}")
    if len({py_version, main_version, web_version}) == 1:
        return _ok("versions-consistent", f"all report {py_version}")
    return _fail(
        "versions-consistent",
        f"mismatch: pyproject={py_version!r} main={main_version!r} webui={web_version!r}",
    )


def check_ci_tiers(root: Path) -> GateResult:
    """Required pyramid jobs exist (fast/integration/unit/nightly)."""
    import yaml

    try:
        ci_jobs = set(
            (yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8")) or {}).get("jobs", {})
        )
        eval_jobs = set(
            (yaml.safe_load((root / ".github/workflows/eval.yml").read_text(encoding="utf-8")) or {}).get("jobs", {})
        )
    except OSError as exc:
        return _fail("ci-tiers", f"cannot read workflows: {exc}")
    missing = {"tests", "lint", "types", "package", "webui", "audit", "sandbox", "browser"} - ci_jobs
    if missing:
        return _fail("ci-tiers", f"ci.yml missing jobs: {sorted(missing)}")
    if "eval-unit" not in eval_jobs or "nightly-eval" not in eval_jobs:
        return _fail("ci-tiers", "eval.yml missing eval-unit/nightly-eval")
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
    for path in [root / "README.md", root / "CLAUDE.md", *(root / "docs").rglob("*.md")]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        nofence = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        if re.search(r"fallback_native[^.\n]{0,80}default[^.\n]{0,20}true", nofence, re.IGNORECASE):
            snippet = nofence[max(0, nofence.lower().find("fallback_native") - 60) :]
            if not re.search(r"default\s*[`'\"]?\s*false", snippet, re.IGNORECASE):
                bad.append(str(path.relative_to(root)))
    if bad:
        return _fail("safety-defaults", f"stale true-default claims in: {bad}")
    return _ok("safety-defaults", "schema + config.yaml + docs agree (fail-closed)")


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


def check_native_consent_gate(root: Path) -> GateResult:
    """Native execution requires explicit env consent (never silent)."""
    sys.path.insert(0, str(root))
    try:
        import os

        from tools.sandbox.manager import NATIVE_CONSENT_ENV, native_execution_consent

        old = os.environ.pop(NATIVE_CONSENT_ENV, None)
        try:
            allowed, _reason = native_execution_consent({"sandbox": {"enabled": False}})
            if allowed:
                return _fail("native-consent", "enabled:false without consent is allowed")
            allowed, _reason = native_execution_consent({"sandbox": {"enabled": True, "fallback_native": True}})
            if allowed:
                return _fail("native-consent", "fallback_native:true without consent is allowed")
        finally:
            if old is not None:
                os.environ[NATIVE_CONSENT_ENV] = old
    except ImportError as exc:
        return _fail("native-consent", f"cannot import: {exc}")
    finally:
        try:
            sys.path.remove(str(root))
        except ValueError:
            pass
    return _ok("native-consent", "host execution is consent-gated")


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


def check_external(root: Path) -> list[GateResult]:
    """Boxes no agent run can satisfy — listed EXTERNAL, never green."""
    _ = root
    return [
        _external(
            "live-eval-backend", "no model backend provisioned from this checkout; provision one for scheduled eval"
        ),
        _external("repeated-trials", "no repeated live-trial artifacts recorded yet; run 5-10x per scenario"),
        _external("branch-rules-applied", "ruleset must be applied by a repo admin; see docs/branch-protection.md"),
        _external("sandbox-image-published", "prebuilt image not yet pushed to GHCR; see sandbox-image.yml"),
    ]


def run_gate(root: Path) -> GateReport:
    report = GateReport()
    report.results += [
        check_versions(root),
        check_ci_tiers(root),
        check_eval_skip_visibility(root),
        check_safety_defaults(root),
        check_safety_suite(root),
        check_negative_controls(root),
        check_provenance_fields(root),
        check_native_consent_gate(root),
        check_docs_contract(root),
        *check_external(root),
    ]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="0.69 beta release gate (GO/NO-GO).")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args(argv)
    report = run_gate(Path(args.root).resolve())
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
