"""CLI wiring tests for the graded eval loop (Feature 1).

Covers the ``--eval`` nargs="*" conversion (legacy ``--eval --target`` path
preserved), ``--eval-list``, and the ``--save-baseline`` / ``--check-regression``
composition. All dispatch tests patch the eval-harness entry points — no
docker, network, or model calls.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from main import parse_args


def test_eval_flag_with_target_parses_legacy_shape() -> None:
    # ``--eval --target X``: nargs="*" consumes nothing before the next option,
    # so eval is an empty list — the legacy single-target path keys off --target.
    args = parse_args(["--eval", "--target", "10.0.0.5"])
    assert args.eval == []
    assert args.target == "10.0.0.5"


def test_eval_flag_default_none() -> None:
    args = parse_args(["--target", "10.0.0.5"])
    assert args.eval is None


def test_eval_accepts_target_ids() -> None:
    args = parse_args(["--eval", "dvwa", "juice_shop"])
    assert args.eval == ["dvwa", "juice_shop"]


def test_eval_bare_is_empty_list() -> None:
    args = parse_args(["--eval"])
    assert args.eval == []


def test_new_eval_flags_parse() -> None:
    args = parse_args(["--eval-list"])
    assert args.eval_list is True
    args = parse_args(["--eval", "--save-baseline", "--check-regression"])
    assert args.save_baseline is True
    assert args.check_regression is True


# --- --eval-list dispatch ---


def test_eval_list_prints_targets_and_exits_zero(monkeypatch, tmp_path, capsys):
    import main as main_mod

    eval_dir = tmp_path / "eval_targets"
    eval_dir.mkdir()
    (eval_dir / "dvwa.oracle.json").write_text(
        json.dumps({"target_id": "dvwa", "flags": [{"id": "f1"}, {"id": "f2"}]}),
        encoding="utf-8",
    )
    (eval_dir / "juice_shop.oracle.json").write_text(
        json.dumps({"target_id": "juice_shop", "flags": []}),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    rc = main_mod.main(["--eval-list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dvwa\t2 flags" in out
    assert "juice_shop\t0 flags" in out


# --- legacy --eval --target path ---


def test_legacy_eval_target_routes_to_run_eval(monkeypatch, tmp_path):
    import main as main_mod

    calls: list[object] = []

    async def _fake_run_eval(args):  # noqa: ANN001
        calls.append(args)
        return 7

    monkeypatch.setattr("tools.eval_harness.run_eval", _fake_run_eval)

    rc = main_mod.main(["--eval", "--target", "10.0.0.5", "--config", str(tmp_path / "config.yaml")])
    assert rc == 7
    assert len(calls) == 1


# --- graded suite path ---


class _FakeReport:
    def render_markdown(self) -> str:
        return "EVAL REPORT (fake)"


def _patch_graded(monkeypatch, *, regression=(True, ["all targets at baseline"]), report=None):
    import tools.eval_harness as eh

    seen: dict[str, object] = {}

    async def _fake_run_graded_eval(target_ids, config, **kwargs):
        seen["target_ids"] = target_ids
        seen["config"] = config
        return report if report is not None else _FakeReport()

    def _fake_save_baseline(report, baseline_path):  # noqa: ARG001
        seen["baseline_saved"] = str(baseline_path)
        return baseline_path

    def _fake_check_regression(report, baseline_path, tolerance=0.05):  # noqa: ARG001
        seen["tolerance"] = tolerance
        return regression

    monkeypatch.setattr(eh, "run_graded_eval", _fake_run_graded_eval)
    monkeypatch.setattr(eh, "save_baseline", _fake_save_baseline)
    monkeypatch.setattr(eh, "check_regression", _fake_check_regression)
    return seen


def test_graded_eval_routes_to_run_graded_eval(monkeypatch, tmp_path):
    import main as main_mod

    seen = _patch_graded(monkeypatch)

    rc = main_mod.main(["--eval", "dvwa", "--config", str(tmp_path / "config.yaml")])
    assert rc == 0
    assert seen["target_ids"] == ["dvwa"]


def test_graded_eval_no_ids_passes_none_for_all_targets(monkeypatch, tmp_path):
    import main as main_mod

    seen = _patch_graded(monkeypatch)

    rc = main_mod.main(["--eval", "--config", str(tmp_path / "config.yaml")])
    assert rc == 0
    assert seen["target_ids"] is None


def test_check_regression_failure_exits_nonzero(monkeypatch, tmp_path):
    import main as main_mod

    _patch_graded(monkeypatch, regression=(False, ["regressed: dvwa 0.20 < 0.50 - 0.05"]))

    rc = main_mod.main(["--eval", "--check-regression", "--config", str(tmp_path / "config.yaml")])
    assert rc == 1


def test_save_baseline_composes_with_eval(monkeypatch, tmp_path):
    import main as main_mod

    seen = _patch_graded(monkeypatch)

    rc = main_mod.main(["--eval", "--save-baseline", "--config", str(tmp_path / "config.yaml")])
    assert rc == 0
    assert "baseline_saved" in seen


def test_baseline_flags_without_eval_exit_two(monkeypatch):
    import main as main_mod

    for flag in ("--save-baseline", "--check-regression"):
        rc = main_mod.main([flag])
        assert rc == 2, f"{flag} without --eval must exit 2"


def test_run_graded_eval_importable() -> None:
    from tools.eval_harness import run_graded_eval

    assert asyncio.iscoroutinefunction(run_graded_eval)


@pytest.mark.parametrize("argv", [["--eval"], ["--eval", "dvwa"]])
def test_eval_dispatch_does_not_reach_exploit_paths(monkeypatch, tmp_path, argv):
    """The graded dispatch returns before any exploit-session plumbing runs."""
    import main as main_mod

    _patch_graded(monkeypatch)

    def _boom(*_a, **_k):  # pragma: no cover - must never be reached
        raise AssertionError("eval dispatch must not touch the exploit path")

    monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _boom, raising=False)
    rc = main_mod.main([*argv, "--config", str(tmp_path / "config.yaml")])
    assert rc == 0
