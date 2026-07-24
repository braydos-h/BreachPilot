"""Regression tests for tools/metasploit_bridge.py.

Covers:
- H15: kill_session sends ``sessions -k {id}`` (single session), not ``-K`` (all sessions)
- H15: background_session sends ``sessions -d {id}``, not ``-K``
- M24: run_auxiliary always sets RHOSTS from target_ip and does not let caller
  options override RHOSTS
- M25: msfvenom preserves a quoted value containing spaces as a single token
  (uses shlex.split instead of str.split)

The console / tmux layer is mocked — no live msfconsole, msfvenom, or tmux is
launched.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.metasploit_bridge import MetasploitBridge, MsfPayloadGenerator


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def bridge(tmp_path: Path) -> MetasploitBridge:
    """A MetasploitBridge with a fake session manager (no tmux) on a temp dir."""
    fake_sm = MagicMock()
    return MetasploitBridge(tmp_path, session_manager=fake_sm)


# ── H15: kill_session / background_session ─────────────────────────────────


def test_kill_session_uses_lowercase_k_for_single_session(bridge: MetasploitBridge) -> None:
    """kill_session must send ``sessions -k {id}``, never ``-K`` (kills all)."""
    captured: dict[str, object] = {}

    def fake_execute(command, wait_seconds=2.0, read_lines=100):
        captured["command"] = command
        captured["wait_seconds"] = wait_seconds
        return {"success": True, "command": command, "output": ""}

    bridge._console.execute = fake_execute  # type: ignore[assignment]

    result = bridge.kill_session(3)

    assert captured["command"] == "sessions -k 3"
    assert "-K" not in captured["command"]
    assert result["success"] is True


def test_background_session_uses_dash_d_not_dash_K(bridge: MetasploitBridge) -> None:
    """background_session must send ``sessions -d {id}`` (detach), not ``-K``."""
    captured: dict[str, object] = {}

    def fake_execute(command, wait_seconds=2.0, read_lines=100):
        captured["command"] = command
        return {"success": True, "command": command, "output": ""}

    bridge._console.execute = fake_execute  # type: ignore[assignment]

    result = bridge.background_session(5)

    assert captured["command"] == "sessions -d 5"
    assert "-K" not in captured["command"]
    assert result["success"] is True


def test_kill_session_marks_session_dead_in_state(bridge: MetasploitBridge) -> None:
    """kill_session should keep the status='dead' bookkeeping + _save_state."""
    from tools.metasploit_bridge import MsfSessionInfo

    bridge._console.execute = lambda command, wait_seconds=2.0, read_lines=100: {
        "success": True, "command": command, "output": "",
    }
    bridge._sessions[7] = MsfSessionInfo(
        session_id=7, session_type="meterpreter", target_ip="10.0.0.7",
        target_port=0, local_ip="", local_port=0, platform="win64",
    )

    bridge.kill_session(7)

    assert bridge._sessions[7].status == "dead"


# ── M24: run_auxiliary RHOSTS handling ─────────────────────────────────────


def _run_auxiliary_capture(bridge: MetasploitBridge) -> list[str]:
    """Patch the console send/read layer and return the list of sent commands."""
    sent: list[str] = []

    bridge._console.is_running = lambda: True  # type: ignore[assignment]
    bridge._console._send_command = lambda cmd: (sent.append(cmd), True)[1]  # type: ignore[assignment]
    bridge._console._read_output = lambda lines=200: ""  # type: ignore[assignment]
    return sent


def test_run_auxiliary_sets_rhosts_from_target_ip(bridge: MetasploitBridge) -> None:
    """Even with options supplied, RHOSTS must come from target_ip, not options."""
    sent = _run_auxiliary_capture(bridge)

    bridge.run_auxiliary(
        "auxiliary/scanner/portscan/tcp",
        "10.0.0.50",
        options={"PORTS": "80"},
    )

    assert "set RHOSTS 10.0.0.50" in sent
    assert "use auxiliary/scanner/portscan/tcp" in sent
    assert "set PORTS 80" in sent
    assert "run" in sent


def test_run_auxiliary_does_not_let_options_override_rhosts(bridge: MetasploitBridge) -> None:
    """A caller-supplied RHOSTS key must be ignored — target_ip wins."""
    sent = _run_auxiliary_capture(bridge)

    bridge.run_auxiliary(
        "auxiliary/scanner/portscan/tcp",
        "10.0.0.50",
        options={"RHOSTS": "1.1.1.1", "PORTS": "443"},
    )

    rhosts_lines = [c for c in sent if c.startswith("set RHOSTS")]
    assert rhosts_lines == ["set RHOSTS 10.0.0.50"]
    # The malicious/erroneous override must never appear.
    assert "set RHOSTS 1.1.1.1" not in sent
    assert "set PORTS 443" in sent


def test_run_auxiliary_without_options_still_sets_rhosts(bridge: MetasploitBridge) -> None:
    """No options → RHOSTS still set from target_ip (regression for M24)."""
    sent = _run_auxiliary_capture(bridge)

    bridge.run_auxiliary("auxiliary/scanner/portscan/tcp", "192.168.1.10")

    assert "set RHOSTS 192.168.1.10" in sent
    assert "run" in sent


# ── M25: msfvenom shlex tokenization ──────────────────────────────────────


def test_msfvenom_preserves_quoted_value_with_spaces(tmp_path: Path) -> None:
    """A quoted option value containing spaces must remain a single token.

    str.split() would break ``Custom="some value with spaces"`` into multiple
    tokens; shlex.split keeps it intact.
    """
    gen = MsfPayloadGenerator(tmp_path)

    captured: dict[str, object] = {}

    def fake_run(cmd_parts, capture_output=True, text=True, timeout=300):
        captured["cmd_parts"] = list(cmd_parts)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("tools.metasploit_bridge.shutil.which", return_value="/usr/bin/msfvenom"), \
         patch("tools.metasploit_bridge.subprocess.run", side_effect=fake_run):
        result = gen.generate(
            payload_type="meterpreter/reverse_tcp",
            lhost="10.0.0.1",
            lport=4444,
            fmt="exe",
            platform="windows",
            arch="x64",
            options='Custom="some value with spaces"',
        )

    assert result["success"] is True, result
    parts = captured["cmd_parts"]
    # The whole ``Custom=some value with spaces`` must be one token, not split
    # into ['Custom=some', 'value', 'with', 'spaces"'].
    assert "Custom=some value with spaces" in parts
    # Sanity: the leading fixed parts are intact.
    assert parts[0] == "msfvenom"
    assert "-p" in parts


def test_msfvenom_returns_error_on_unbalanced_quotes(tmp_path: Path) -> None:
    """Malformed options (unbalanced quotes) must yield an error dict, not crash."""
    gen = MsfPayloadGenerator(tmp_path)

    with patch("tools.metasploit_bridge.shutil.which", return_value="/usr/bin/msfvenom"):
        result = gen.generate(
            payload_type="meterpreter/reverse_tcp",
            lhost="10.0.0.1",
            lport=4444,
            fmt="exe",
            platform="windows",
            arch="x64",
            options='Custom=unbalanced "quotes',
        )

    assert result["success"] is False
    assert result["status"] == "error"
    assert "quote" in result["error"].lower() or "unbalanced" in result["error"].lower()