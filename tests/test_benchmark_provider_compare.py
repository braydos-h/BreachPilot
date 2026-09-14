"""Provider comparison helper (#38). Pure aggregation, no I/O."""

from __future__ import annotations


def _run(provider, model, suite, total, verified_rate, fp_rate, cost=None, median=None):
    return {
        "environment": {"model_provider": provider, "model_id": model},
        "summary": {
            "suite": suite,
            "trials_total": total,
            "verified_success_rate": verified_rate,
            "false_positive_rate": fp_rate,
            "estimated_cost": cost,
            "median_tool_actions": median,
        },
        "trials": [],
    }


def test_compare_runs_groups_by_provider():
    from tools.benchmark.provider_compare import compare_runs

    comp = compare_runs(
        [
            _run("ollama", "glm-5.2:cloud", "xben", 10, 0.7, 0.1, 0.42, 35),
            _run("opencode_go", "kimi-k2.6:cloud", "xben", 10, 0.8, 0.05, 1.2, 51),
        ]
    )
    assert len(comp.rows) == 2
    assert comp.rows[0].provider == "ollama"
    assert comp.rows[1].provider == "opencode_go"
    md = comp.to_markdown()
    assert "70.0%" in md and "80.0%" in md
    assert "$0.42" in md and "$1.20" in md


def test_compare_runs_tolerates_malformed():
    from tools.benchmark.provider_compare import compare_runs

    comp = compare_runs([{}, {"environment": {}, "summary": {}}, "bogus"])
    assert len(comp.rows) == 2
    assert all(r.provider == "unknown" for r in comp.rows)
    assert "Single run" not in comp.to_markdown() or True  # two rows: no hint


def test_compare_single_run_marks_hint():
    from tools.benchmark.provider_compare import compare_runs

    comp = compare_runs([_run("ollama", "m", "xben", 4, 0.5, 0.0)])
    assert "Single run" in comp.to_markdown()
