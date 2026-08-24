"""Regression tests for the ``--long-session`` / ``long_session:`` config block.

Covers the five longevity fixes:
* ``build_cli_exploit_settings`` raises the attack budgets when long-session is
  active and leaves them (and ``long_session_enabled``) untouched otherwise.
* ``_call_ollama_with_tools`` / ``_stream_ollama`` send ``options.num_ctx`` only
  when a context window is supplied (long-session on), and omit it otherwise so
  non-long runs are byte-identical to today.
* ``_build_model_client`` forwards ``timeout=`` to the Ollama client.
* ``SessionState`` persists the compacted ``messages`` only when
  ``persist_messages`` is True (backward compat: old state files load with []).
* ``build_resume_messages`` returns the persisted messages verbatim when on,
  falls back to the condensed rebuild when off.
* ``_compute_swarm_timeout`` raises the deadline from
  ``long_session.swarm_session_timeout_minutes`` and keeps the 300s default.

All tests stub the Ollama client / MCP â€” no live network. Per the project
memory note pytest can't run on the Linux dev box; run on the Windows env:
``python -m pytest tests/test_long_session.py -q``.
"""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

# â”€â”€ 1 & 2: build_cli_exploit_settings budget bumps + off-by-default â”€â”€â”€â”€â”€â”€â”€â”€


def _goal():
    from tools.goal_engine import AttackGoal
    return AttackGoal(name="recon_only", description="recon")


def _base_config() -> dict[str, Any]:
    return {"exploit": {"permission": "read_only"}}


class TestBuildSettingsLongSession:
    def test_long_session_raises_attack_budgets(self):
        from main import build_cli_exploit_settings
        cfg = dict(_base_config())
        cfg["long_session"] = {
            "enabled": False,
            "attack_max_rounds": 200,
            "attack_max_commands": 1000,
            "attack_max_duration_minutes": 720,
            "persist_messages": True,
        }
        settings = build_cli_exploit_settings(
            mode="attack", target_ip="10.0.0.50", goal=_goal(), config=cfg,
            long_session=True,
        )
        assert settings.long_session_enabled is True
        assert settings.attack_max_rounds == 200
        assert settings.attack_max_commands == 1000
        assert settings.attack_max_duration_minutes == 720
        assert settings.persist_messages is True

    def test_long_session_off_by_default(self):
        from main import build_cli_exploit_settings
        settings = build_cli_exploit_settings(
            mode="attack", target_ip="10.0.0.50", goal=_goal(), config=_base_config(),
        )
        assert settings.long_session_enabled is False
        assert settings.persist_messages is False
        # Default attack budgets come from the exploit config defaults, not long_session.
        assert settings.attack_max_rounds == 200  # exploit_cfg default
        assert settings.attack_max_commands == 500  # exploit_cfg default

    def test_long_session_enabled_in_config_activates_without_flag(self):
        from main import build_cli_exploit_settings
        cfg = dict(_base_config())
        cfg["long_session"] = {"enabled": True, "attack_max_rounds": 200}
        settings = build_cli_exploit_settings(
            mode="attack", target_ip="10.0.0.50", goal=_goal(), config=cfg,
        )
        assert settings.long_session_enabled is True
        assert settings.attack_max_rounds == 200

    def test_explicit_max_rounds_wins_over_long_session_block(self):
        from main import build_cli_exploit_settings
        cfg = dict(_base_config())
        cfg["long_session"] = {"enabled": True, "attack_max_rounds": 200, "attack_max_commands": 1000}
        settings = build_cli_exploit_settings(
            mode="attack", target_ip="10.0.0.50", goal=_goal(), config=cfg,
            max_rounds=7, max_commands=9,
        )
        assert settings.attack_max_rounds == 7
        assert settings.attack_max_commands == 9


# â”€â”€ 3 & 4: num_ctx passthrough to Ollama chat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class _RecordingClient:
    """Records the kwargs passed to ``chat``; returns a fixed message shape."""

    def __init__(self, *, content: str = "ok", stream: bool = False):
        self._content = content
        self._stream = stream
        self.calls: list[dict[str, Any]] = []

    def chat(self, model: str, **kwargs):
        self.calls.append(dict(kwargs))
        if self._stream:
            return iter([{"message": {"content": self._content, "role": "assistant"}}])
        return {"message": {"content": self._content, "role": "assistant"}}


class TestNumCtxPassthrough:
    def test_call_ollama_with_tools_passes_num_ctx(self):
        from tools.exploit_agent import _call_ollama_with_tools
        client = _RecordingClient()
        _call_ollama_with_tools(client, "m", [{"role": "user", "content": "hi"}],
                                context_window_tokens=976_000)
        assert client.calls[0]["options"] == {"num_ctx": 976_000}

    def test_call_ollama_with_tools_omits_num_ctx_when_none(self):
        from tools.exploit_agent import _call_ollama_with_tools
        client = _RecordingClient()
        _call_ollama_with_tools(client, "m", [{"role": "user", "content": "hi"}])
        assert "options" not in client.calls[0]

    def test_call_ollama_with_tools_omits_num_ctx_when_zero(self):
        from tools.exploit_agent import _call_ollama_with_tools
        client = _RecordingClient()
        _call_ollama_with_tools(client, "m", [{"role": "user", "content": "hi"}],
                                context_window_tokens=0)
        assert "options" not in client.calls[0]

    @pytest.mark.asyncio
    async def test_stream_ollama_passes_num_ctx(self):
        from tools.exploit_agent import _stream_ollama
        client = _RecordingClient(stream=True)
        await _stream_ollama(client, "m", [{"role": "user", "content": "hi"}],
                            context_window_tokens=976_000)
        assert client.calls[0]["options"] == {"num_ctx": 976_000}

    @pytest.mark.asyncio
    async def test_stream_ollama_omits_num_ctx_when_none(self):
        from tools.exploit_agent import _stream_ollama
        client = _RecordingClient(stream=True)
        await _stream_ollama(client, "m", [{"role": "user", "content": "hi"}])
        assert "options" not in client.calls[0]


# â”€â”€ 5: _build_model_client forwards timeout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class TestModelClientTimeout:
    def test_build_model_client_forwards_timeout(self, monkeypatch):
        import tools.model_router as mr
        recorded: dict[str, Any] = {}

        class FakeClient:
            def __init__(self, host=None, *, timeout=None, **kwargs):
                recorded["host"] = host
                recorded["timeout"] = timeout

            def list(self):  # noqa: A003 â€” mirror real client
                return []

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", FakeClient)
        mr._build_model_client("m", host="http://h", alias="a", request_timeout_seconds=123.0)
        assert recorded["timeout"] == 123.0

    def test_build_model_client_omits_timeout_when_none(self, monkeypatch):
        import tools.model_router as mr
        recorded: dict[str, Any] = {}

        class FakeClient:
            def __init__(self, host=None, **kwargs):
                recorded["kwargs"] = kwargs

            def list(self):
                return []

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", FakeClient)
        mr._build_model_client("m", host="http://h", alias="a")
        assert "timeout" not in recorded["kwargs"]


# â”€â”€ 5b: cloud-only build â€” no probe, no fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class TestBuildModelClientCloudOnly:
    """Cloud-only: ``_build_model_client`` points the Ollama client at the
    given host (default https://api.ollama.com) with no reachability probe
    and no localâ†’cloud fallback. Auth is the ollama client's job
    (``OLLAMA_API_KEY`` env), not ours."""

    def test_uses_given_host_directly(self, monkeypatch):
        import tools.model_router as mr

        constructed: list[str] = []

        class _Client:
            def __init__(self, host=None, **kwargs):
                constructed.append(host)
                self.host = host

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        mr._build_model_client("m", host="http://my-host", alias="a")
        # Exactly one client built, against the given host â€” no probe, no retry.
        assert constructed == ["http://my-host"]

    def test_defaults_to_cloud_host(self, monkeypatch):
        import tools.model_router as mr

        constructed: list[str] = []

        class _Client:
            def __init__(self, host=None, **kwargs):
                constructed.append(host)

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        mr._build_model_client("m", alias="a")
        assert constructed == [mr.OLLAMA_CLOUD_HOST]

    def test_no_list_probe_called(self, monkeypatch):
        """Building a client must not call ``list()`` â€” cloud-only builds skip
        the reachability probe entirely (auth failures surface on the first
        real chat, not a boot-time probe)."""
        import tools.model_router as mr

        class _Client:
            def __init__(self, host=None, **kwargs):
                self.host = host

            def list(self):  # pragma: no cover - should not be called
                raise AssertionError("list() probe must not run in cloud-only mode")

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        mr._build_model_client("m", host="http://h", alias="a")

    def test_no_warning_or_info_printed(self, monkeypatch, capsys):
        import tools.model_router as mr

        class _Client:
            def __init__(self, host=None, **kwargs):
                pass

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        for alias in ("a", "b", "c"):
            mr._build_model_client("m", host="http://h", alias=alias)
        out = capsys.readouterr().out
        assert "[WARNING]" not in out
        assert "Ollama Cloud" not in out
        assert "falling back" not in out

    def test_chat_delegates_to_built_client(self, monkeypatch):
        """The returned ModelClient's chat hits whatever host was passed in
        (no second client is constructed during chat)."""
        import tools.model_router as mr

        constructed: list[str] = []

        class _Client:
            def __init__(self, host=None, **kwargs):
                constructed.append(host)
                self.host = host

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        client = mr._build_model_client("m", host="http://h", alias="a")
        constructed.clear()
        client.chat([{"role": "user", "content": "hi"}])
        assert constructed == []  # no new client built during chat


# â”€â”€ 6 & 7: SessionState persist_messages roundtrip + resume â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class TestSessionStatePersist:
    def test_persist_messages_on_roundtrip(self, tmp_path: Path):
        from tools.session_manager import SessionState
        s = SessionState(session_id="s1", target_ip="10.0.0.50", target_cve="",
                         persist_messages=True,
                         messages=[{"role": "system", "content": "p"},
                                   {"role": "user", "content": "u"}])
        blob = s.to_json()
        assert blob["messages"] == [{"role": "system", "content": "p"},
                                    {"role": "user", "content": "u"}]
        assert blob["persist_messages"] is True
        back = SessionState.from_json(blob)
        assert back.persist_messages is True
        assert back.messages == [{"role": "system", "content": "p"},
                                  {"role": "user", "content": "u"}]

    def test_persist_messages_off_drops_messages(self, tmp_path: Path):
        from tools.session_manager import SessionState
        s = SessionState(session_id="s1", target_ip="10.0.0.50", target_cve="",
                         persist_messages=False,
                         messages=[{"role": "system", "content": "p"}])
        blob = s.to_json()
        assert blob["messages"] == []
        back = SessionState.from_json(blob)
        assert back.persist_messages is False
        assert back.messages == []

    def test_old_state_file_without_persist_flag_loads_empty(self, tmp_path: Path):
        from tools.session_manager import SessionState
        # An old state file has no persist_messages field and messages: [].
        legacy = {
            "session_id": "s1", "target_ip": "10.0.0.50", "target_cve": "",
            "messages": [],
        }
        back = SessionState.from_json(legacy)
        assert back.persist_messages is False
        assert back.messages == []

    def test_build_resume_messages_uses_persisted_when_on(self, tmp_path: Path):
        from tools.session_manager import SessionManager, SessionState
        mgr = SessionManager(tmp_path)
        mgr._state = SessionState(
            session_id="s1", target_ip="10.0.0.50", target_cve="",
            persist_messages=True,
            messages=[{"role": "system", "content": "p"},
                      {"role": "user", "content": "u"}],
        )
        out = mgr.build_resume_messages("SYSTEM")
        assert out == [{"role": "system", "content": "p"},
                       {"role": "user", "content": "u"}]

    def test_build_resume_messages_falls_back_when_off(self, tmp_path: Path):
        from tools.session_manager import SessionManager, SessionState
        mgr = SessionManager(tmp_path)
        mgr._state = SessionState(
            session_id="s1", target_ip="10.0.0.50", target_cve="",
            persist_messages=False,
            context_history=[{"timestamp": 0, "action": "scan", "result": "r", "success": True}],
        )
        out = mgr.build_resume_messages("SYSTEM")
        # Condensed rebuild: starts with the system prompt + a resume user msg.
        assert out[0]["role"] == "system"
        assert out[0]["content"] == "SYSTEM"
        assert any(m["role"] == "tool" for m in out)


# â”€â”€ 8: _compute_swarm_timeout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _args(**kw) -> Namespace:
    base = dict(long_session=False)
    base.update(kw)
    return Namespace(**base)


class TestComputeSwarmTimeout:
    def test_default_is_300s(self):
        from main import _compute_swarm_timeout
        assert _compute_swarm_timeout({}, _args()) == 300.0

    def test_long_session_flag_raises_from_config(self):
        from main import _compute_swarm_timeout
        cfg = {"long_session": {"swarm_session_timeout_minutes": 30}}
        assert _compute_swarm_timeout(cfg, _args(long_session=True)) == 1800.0

    def test_long_session_enabled_in_config_raises(self):
        from main import _compute_swarm_timeout
        cfg = {"long_session": {"enabled": True, "swarm_session_timeout_minutes": 45}}
        assert _compute_swarm_timeout(cfg, _args()) == 2700.0

    def test_swarm_session_timeout_seconds_override(self):
        from main import _compute_swarm_timeout
        cfg = {"swarm": {"session_timeout_seconds": 600}}
        assert _compute_swarm_timeout(cfg, _args()) == 600.0

    def test_long_session_wins_over_swarm_override(self):
        from main import _compute_swarm_timeout
        cfg = {
            "long_session": {"enabled": True, "swarm_session_timeout_minutes": 20},
            "swarm": {"session_timeout_seconds": 600},
        }
        assert _compute_swarm_timeout(cfg, _args()) == 1200.0
