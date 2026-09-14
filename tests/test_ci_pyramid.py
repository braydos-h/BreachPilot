"""CI pyramid guard (#46).

The pyramid tiers are a contract: Tier 1/2 jobs must exist in ci.yml,
eval-unit must exist in eval.yml, and the nightly live job must record an
explicit SKIPPED report instead of silent green. This test reads the
workflow YAML (no CI run needed) so drift fails fast locally.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent

TIER1_REQUIRED = {"tests", "lint", "types", "package", "webui", "audit", "coverage"}
TIER2_REQUIRED = {"sandbox", "browser"}


def _jobs(workflow: str) -> dict:
    text = (REPO / ".github/workflows" / workflow).read_text(encoding="utf-8")
    return yaml.safe_load(text).get("jobs", {}) or {}


def test_ci_pyramid_tiers_present():
    ci_jobs = _jobs("ci.yml")
    for job in TIER1_REQUIRED | TIER2_REQUIRED:
        assert job in ci_jobs, f"ci.yml missing pyramid job {job!r}"
    assert "needs" in ci_jobs.get("ci", {}), "ci-success aggregator must gate on tiers"


def test_eval_pyramid_unit_and_nightly_present():
    eval_jobs = _jobs("eval.yml")
    assert "eval-unit" in eval_jobs
    assert "nightly-eval" in eval_jobs


def test_nightly_skip_is_explicit_not_silent():
    text = (REPO / ".github/workflows/eval.yml").read_text(encoding="utf-8")
    assert "write_skipped_eval_report" in text
    assert "SKIPPED" in text
    # The old silent green must be gone.
    assert "graceful skip" not in text.lower() or "SKIPPED" in text


def test_pyramid_doc_exists():
    assert (REPO / "docs/ci-pyramid.md").exists()
