"""Tests for ``--ctf`` CTF autopilot mode (D2).

The mode runs the standard attack flow against an operator-authorized CTF
target and stops when the goal is heuristically met (flag marker / uid=0 /
port-marker). It does NOT bypass the allowlist — the operator passes
``--target <ctf_target_ip>`` and the normal target-IP lock applies.
"""

from __future__ import annotations

import socket
import threading

from tools.ctf_mode import (
    CtfGoal,
    default_goal_for_target,
    goal_met_from_result,
    port_responds_with,
    run_ctf,
)

# ── CtfGoal ──────────────────────────────────────────────────────────────────


def test_ctf_goal_defaults_not_configured():
    g = CtfGoal()
    assert g.is_configured is False


def test_ctf_goal_flag_path_configured():
    assert CtfGoal(flag_path="/root/flag.txt").is_configured is True


def test_ctf_goal_root_shell_configured():
    assert CtfGoal(root_shell=True).is_configured is True


def test_ctf_goal_port_marker_configured():
    assert CtfGoal(port=8080, marker="FLAG{x}").is_configured is True


def test_default_goal_for_target():
    g = default_goal_for_target("10.0.0.50")
    assert g.root_shell is True
    assert g.is_configured is True


# ── goal_met_from_result — flag marker detection ─────────────────────────────


def test_goal_met_flag_marker_in_outcome_summary():
    result = {"outcome_summary": "compromises: 1; FLAG{pwned} detected"}
    assert goal_met_from_result(result, CtfGoal(root_shell=False)) is True


def test_goal_met_flag_marker_in_messages():
    result = {
        "outcome_summary": "",
        "messages": [{"content": "root@victim:~# cat /root/flag.txt\nflag{you_win}"}],
    }
    assert goal_met_from_result(result, CtfGoal(root_shell=False)) is True


def test_goal_met_flag_marker_in_records():
    result = {
        "outcome_summary": "",
        "records": [{"command": "cat /flag.txt", "output": "CTF{captured_the_flag}"}],
    }
    assert goal_met_from_result(result, CtfGoal(root_shell=False)) is True


def test_goal_met_no_flag_not_met():
    result = {"outcome_summary": "compromises: 0; no access"}
    assert goal_met_from_result(result, CtfGoal(root_shell=False)) is False


# ── goal_met_from_result — root shell detection ──────────────────────────────


def test_goal_met_root_shell_uid0():
    result = {"outcome_summary": "uid=0(root) gid=0(root) groups=0(root)"}
    assert goal_met_from_result(result, CtfGoal(root_shell=True)) is True


def test_goal_met_root_shell_not_met():
    result = {"outcome_summary": "uid=1000(ctf) gid=1000(ctf)"}
    assert goal_met_from_result(result, CtfGoal(root_shell=True)) is False


# ── goal_met_from_result — flag path ─────────────────────────────────────────


def test_goal_met_flag_path_in_output():
    result = {"outcome_summary": "cat /root/flag.txt -> flag{path_worked}"}
    g = CtfGoal(flag_path="/root/flag.txt", root_shell=False)
    assert goal_met_from_result(result, g) is True


def test_goal_met_flag_path_not_present():
    result = {"outcome_summary": "no flag read"}
    g = CtfGoal(flag_path="/root/flag.txt", root_shell=False)
    assert goal_met_from_result(result, g) is False


# ── goal_met_from_result — robustness ────────────────────────────────────────


def test_goal_met_none_result():
    assert goal_met_from_result(None, CtfGoal()) is False


def test_goal_met_empty_result():
    assert goal_met_from_result({}, CtfGoal()) is False


def test_goal_met_malformed_messages():
    result = {"messages": "not a list"}
    assert goal_met_from_result(result, CtfGoal()) is False


# ── port_responds_with — direct TCP probe ────────────────────────────────────


def _start_marker_server(port: int, marker: str) -> socket.socket:
    """Start a raw TCP server that writes ``marker`` immediately on connect.

    ``port_responds_with`` does a bare recv (no request line), so we use a
    raw socket server, not HTTP.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.sendall(marker.encode())
            conn.close()
        except (OSError, socket.timeout):
            pass

    threading.Thread(target=_serve, daemon=True).start()
    # Give the listener a moment to bind.
    import time
    time.sleep(0.1)
    return srv


def test_port_responds_with_match(tmp_path):
    srv = _start_marker_server(18099, "FLAG{port_marker}")
    try:
        assert port_responds_with("127.0.0.1", 18099, "FLAG{port_marker}") is True
    finally:
        srv.close()


def test_port_responds_with_no_match(tmp_path):
    srv = _start_marker_server(18098, "nothing useful here")
    try:
        assert port_responds_with("127.0.0.1", 18098, "FLAG{port_marker}") is False
    finally:
        srv.close()


def test_port_responds_with_connection_refused():
    # Nothing listening on this port (highly likely).
    assert port_responds_with("127.0.0.1", 1, "anything") is False


def test_port_responds_with_empty_args():
    assert port_responds_with("", 0, "") is False


# ── run_ctf CLI entry ────────────────────────────────────────────────────────


def test_run_ctf_requires_target(tmp_path, monkeypatch):
    """``--ctf`` without ``--target`` returns 2 (usage error)."""
    monkeypatch.chdir(tmp_path)
    from argparse import Namespace
    args = Namespace(target="", ctf=True, config=tmp_path / "config.yaml")
    rc = run_ctf(args)
    assert rc == 2


def test_run_ctf_respects_allowlist(tmp_path, monkeypatch):
    """CTF mode does NOT bypass the allowlist — it reuses the standard flow.

    We patch run_eval to a stub that records the target and returns 0 (so the
    goal-completion check runs). The test confirms run_ctf passes the target
    through to the run flow without bypassing it.
    """
    monkeypatch.chdir(tmp_path)
    seen = {}

    async def _fake_run_eval(args):
        seen["target"] = getattr(args, "target", "")
        # Write a minimal eval report so the goal-completion path can read it.
        import json
        eval_dir = tmp_path / "reports" / "eval" / "run1"
        eval_dir.mkdir(parents=True, exist_ok=True)
        (eval_dir / "eval_report.json").write_text(
            json.dumps({"outcome_summary": "FLAG{ctf_test_win}"}), encoding="utf-8",
        )
        return 0

    monkeypatch.setattr("tools.eval_harness.run_eval", _fake_run_eval)
    # goal_met_from_result will find the flag marker in the stub report.
    from argparse import Namespace
    args = Namespace(
        target="10.0.0.50", ctf=True, config=tmp_path / "config.yaml",
        ctf_flag_path="", ctf_root_shell=True, ctf_port=0, ctf_marker="",
    )
    rc = run_ctf(args)
    assert rc == 0  # goal met (FLAG marker in report)
    assert seen["target"] == "10.0.0.50"  # target passed through


def test_run_ctf_goal_not_met_returns_1(tmp_path, monkeypatch):
    """When the run succeeds but the goal is not met, run_ctf returns 1."""
    monkeypatch.chdir(tmp_path)

    async def _fake_run_eval(args):
        import json
        eval_dir = tmp_path / "reports" / "eval" / "run2"
        eval_dir.mkdir(parents=True, exist_ok=True)
        (eval_dir / "eval_report.json").write_text(
            json.dumps({"outcome_summary": "compromises: 0; no access"}), encoding="utf-8",
        )
        return 0

    monkeypatch.setattr("tools.eval_harness.run_eval", _fake_run_eval)
    from argparse import Namespace
    args = Namespace(
        target="10.0.0.50", ctf=True, config=tmp_path / "config.yaml",
        ctf_flag_path="", ctf_root_shell=False, ctf_port=0, ctf_marker="",
    )
    # default_goal_for_target kicks in (root_shell=True), but the report has
    # no uid=0 and no flag marker → not met.
    rc = run_ctf(args)
    assert rc == 1


def test_run_ctf_eval_failure_returns_1(tmp_path, monkeypatch):
    """When the underlying run fails, run_ctf returns 1."""
    monkeypatch.chdir(tmp_path)

    async def _fake_run_eval(args):
        return 1

    monkeypatch.setattr("tools.eval_harness.run_eval", _fake_run_eval)
    from argparse import Namespace
    args = Namespace(
        target="10.0.0.50", ctf=True, config=tmp_path / "config.yaml",
        ctf_flag_path="", ctf_root_shell=True, ctf_port=0, ctf_marker="",
    )
    rc = run_ctf(args)
    assert rc == 1
