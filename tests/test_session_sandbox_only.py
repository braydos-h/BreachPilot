"""Agent session controls must never launch or control host processes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from tools.mcp_tools.sessions import register_session_tools


class _ToolRegistry:
    def __init__(self) -> None:
        self.tools = {}

    def tool(self):
        return lambda fn: self.tools.setdefault(fn.__name__, fn)


def test_session_family_fails_closed_until_worker_backed(tmp_path: Path) -> None:
    registry = _ToolRegistry()
    ctx = SimpleNamespace(audit_tool=lambda fn: fn)
    register_session_tools(registry, ctx=ctx)

    calls = {
        "start_tmux_session": {"name": "session", "command": "id"},
        "send_to_session": {"name": "session", "input_text": "id"},
        "read_session_output": {"name": "session"},
        "kill_session": {"name": "session"},
        "start_background_job": {"name": "job", "command": "id"},
        "read_job_output": {"name": "job"},
        "stop_background_job": {"name": "job"},
        "start_listener": {"name": "listener", "port": 4444},
        "read_listener_output": {"name": "listener"},
        "stop_listener": {"name": "listener"},
        "list_sessions": {},
        "list_processes": {},
        "kill_process": {"name_or_pid": "1"},
    }
    assert set(calls) <= set(registry.tools)
    for name, arguments in calls.items():
        result = registry.tools[name](**arguments)
        assert "SANDBOX_UNSUPPORTED" in result
        assert "sandbox-backed implementation" in result
