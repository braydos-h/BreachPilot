"""Regression coverage for honest benchmark report denominators."""

from __future__ import annotations

from tools.benchmark.report import render_report_html, render_report_markdown


def _empty_outcome_summary():
    return {
        "solved": 0,
        "trials_total": 2,
        "trials_completed": 0,
        "verified_success_rate": None,
        "false_positive_rate": None,
        "infra_error_count": 1,
        "skipped_count": 1,
        "scenarios": [
            {
                "scenario_id": "sandboxed",
                "verified": 0,
                "trials": 2,
                "trials_completed": 0,
                "success_probability": None,
                "ci95_low": None,
                "ci95_high": None,
            }
        ],
    }


def test_reports_show_empty_outcome_rates_as_unavailable():
    run = {"run_id": "r-empty", "suite": "xben", "environment": {}, "config": {"trials": 2}}
    summary = _empty_outcome_summary()

    markdown = render_report_markdown(run, summary)
    html = render_report_html(run, summary)

    assert "0/0 completed" in markdown
    assert "(2 total trials)" in markdown
    assert "Verified success rate**: n/a" in markdown
    assert "| 0 / 2 | n/a | n/a |" in markdown
    assert "Infrastructure errors / skipped**: 1 / 1" in markdown
    assert "Scope violations reaching network layer**: n/a (not measured)" in markdown
    assert "0/0 completed verified" in html
    assert "Infra errors / skipped: 1 / 1" in html
    assert ">n/a</td>" in html
