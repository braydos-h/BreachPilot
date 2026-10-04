"""Checker failures must not pass the debt gate or erase its baseline."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def debt_gate():
    path = Path(__file__).resolve().parent.parent / "scripts" / "mypy_debt.py"
    spec = importlib.util.spec_from_file_location("mypy_debt_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [
        (1, "", "No module named mypy"),
        (2, "", "mypy: invalid configuration"),
        (2, "tools/example.py:5: error: incompatible type [arg-type]\n", "INTERNAL ERROR"),
        (-9, "", ""),
        (1, "Unrecognized diagnostic format", ""),
        (0, "tools/example.py:5: error: incompatible type [arg-type]\n", ""),
    ],
)
@pytest.mark.parametrize("arguments", [[], ["--update"]])
def test_failed_measurement_preserves_baseline(
    debt_gate, monkeypatch, tmp_path, capsys, returncode, stdout, stderr, arguments
):
    baseline = tmp_path / "mypy-baseline.txt"
    original = "total: 1\ntools/example.py 1\n"
    baseline.write_text(original, encoding="utf-8")
    monkeypatch.setattr(debt_gate, "BASELINE_PATH", baseline)
    monkeypatch.setattr(
        debt_gate.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], returncode, stdout, stderr),
    )

    assert debt_gate.main(arguments) == 1
    assert baseline.read_text(encoding="utf-8") == original
    assert "checker failure; baseline unchanged" in capsys.readouterr().out


@pytest.mark.parametrize("failure", [OSError("cannot start checker"), subprocess.TimeoutExpired("mypy", 570)])
def test_checker_start_or_timeout_failure_cleans_resources(debt_gate, monkeypatch, tmp_path, failure):
    resources = []

    def fail(command, **kwargs):
        resources.append(Path(command[command.index("--config-file") + 1]))
        resources.append(Path(command[command.index("--cache-dir") + 1]))
        raise failure

    baseline = tmp_path / "baseline.txt"
    baseline.write_text("total: 1\ntools/example.py 1\n", encoding="utf-8")
    monkeypatch.setattr(debt_gate, "BASELINE_PATH", baseline)
    monkeypatch.setattr(debt_gate.subprocess, "run", fail)

    assert debt_gate.main(["--update"]) == 1
    assert baseline.read_text(encoding="utf-8") == "total: 1\ntools/example.py 1\n"
    assert not resources[0].exists()
    assert not resources[1].exists()


def test_real_type_errors_are_counted_and_new_debt_rejected(debt_gate, monkeypatch, tmp_path):
    output = (
        "tools/example.py:5: error: incompatible type [arg-type]\n"
        "tools/new.py:9: error: missing attribute [attr-defined]\n"
    )
    monkeypatch.setattr(
        debt_gate.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, output, ""),
    )
    baseline = tmp_path / "baseline.txt"
    baseline.write_text("total: 1\ntools/example.py 1\n", encoding="utf-8")
    monkeypatch.setattr(debt_gate, "BASELINE_PATH", baseline)

    assert debt_gate.run_mypy() == ({"tools/example.py": 1, "tools/new.py": 1}, 2, output)
    assert debt_gate.main([]) == 1
    assert baseline.read_text(encoding="utf-8") == "total: 1\ntools/example.py 1\n"


def test_successful_clean_measurement_can_pay_down_baseline(debt_gate, monkeypatch, tmp_path):
    monkeypatch.setattr(
        debt_gate.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    baseline = tmp_path / "baseline.txt"
    baseline.write_text("total: 1\ntools/example.py 1\n", encoding="utf-8")
    monkeypatch.setattr(debt_gate, "BASELINE_PATH", baseline)

    assert debt_gate.main([]) == 0
    assert debt_gate.main(["--update"]) == 0
    assert debt_gate.load_baseline() == ({}, 0)
