"""Regression tests for the main.py fixes from the lazy-canyon plan.

Covers:
* H9  — ``build_cli_exploit_settings`` resolves the exploit permission from
  config (``exploit.permission``) instead of hardcoding ``FULL_ACCESS`` for
  attack mode / ``APPROVE_ONLY`` for recon mode. A ``read_only`` config must
  NEVER silently become ``FULL_ACCESS`` just because the operator picked
  ``--mode attack``.
* M21 — ``--resume`` restores the saved recon assessment + chosen goal from
  ``recon_assessment.json`` so the resumed run reuses them and skips
  recon-first.
* M20 — ``--swarm`` dispatches on mode: attack mode awaits
  ``AgentLoop.run_autonomous_campaign`` (async); recon mode runs the
  synchronous research loop in a worker thread.

All tests mock subprocess/network — no live tools, no Ollama, no MCP server.
"""

from __future__ import annotations

import asyncio
import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── Shared helpers ─────────────────────────────────────────────────────────


def _make_args(
    tmp_path: Path,
    *,
    target: str = "10.0.0.50",
    mode: str = "recon",
    goal: str = "",
    custom_goal: str = "",
    swarm: bool = False,
    resume: str = "",
    recon_first: bool | None = False,
    yes: bool = True,
) -> Namespace:
    """Build a Namespace matching ``parse_args()`` output for async_main."""
    return Namespace(
        target=target,
        mode=mode,
        goal=goal,
        custom_goal=custom_goal,
        config=Path("config.yaml"),
        model=None,
        model_strategy="default",
        mcp_transport="stdio",
        http_port=None,
        reports_dir=tmp_path / "reports",
        setup_api_keys=False,
        api_key_file=Path("secrets/api_keys.json"),
        no_api_key_prompt=True,
        plain=True,
        stealth=False,
        rotate_ua=False,
        doh=False,
        tui=False,
        menu=False,
        swarm=swarm,
        critic=False,
        reflection=False,
        adaptive_exploits=False,
        multi_model_consult=False,
        observer_mode="hybrid",
        recon_first=recon_first,
        doctor=False,
        demo=False,
        resume=resume,
        json=False,
        quiet=False,
        debug=False,
        yes=yes,
        self_test=False,
        ultrathink=False,
    )


# ── H9: build_cli_exploit_settings resolves permission from config ─────────


class TestBuildCliExploitSettingsPermission:
    """H9: permission must come from config, not be hardcoded per mode."""

    def _goal(self):
        from tools.goal_engine import AttackGoal
        return AttackGoal(name="recon_only", description="recon")

    def test_recon_mode_read_only_config_is_not_full_access(self):
        from main import build_cli_exploit_settings
        from tools.exploit_agent import ExploitPermission
        settings = build_cli_exploit_settings(
            mode="recon",
            target_ip="10.0.0.50",
            goal=self._goal(),
            config={"exploit": {"permission": "read_only"}},
        )
        assert settings.permission != ExploitPermission.FULL_ACCESS, (
            "read_only config resolved to FULL_ACCESS — first-run users could "
            "accidentally fire exploits"
        )

    def test_attack_mode_read_only_config_does_not_upgrade_to_full_access(self):
        """The core H9 regression: attack mode used to hardcode FULL_ACCESS,
        ignoring a read_only config. It must now honor the config."""
        from main import build_cli_exploit_settings
        from tools.exploit_agent import ExploitPermission
        settings = build_cli_exploit_settings(
            mode="attack",
            target_ip="10.0.0.50",
            goal=self._goal(),
            config={"exploit": {"permission": "read_only"}},
        )
        assert settings.permission != ExploitPermission.FULL_ACCESS, (
            "attack mode auto-upgraded a read_only config to FULL_ACCESS"
        )
        # attack_mode flag is orthogonal to permission and should still flip on.
        assert settings.attack_mode is True

    def test_attack_mode_explicit_full_access_config_upgrades(self):
        from main import build_cli_exploit_settings
        from tools.exploit_agent import ExploitPermission
        settings = build_cli_exploit_settings(
            mode="attack",
            target_ip="10.0.0.50",
            goal=self._goal(),
            config={"exploit": {"permission": "full_access"}},
        )
        assert settings.permission == ExploitPermission.FULL_ACCESS
        assert settings.attack_mode is True

    def test_unknown_permission_falls_back_safely(self):
        """A garbage config value must not raise nor grant full access."""
        from main import build_cli_exploit_settings
        from tools.exploit_agent import ExploitPermission
        settings = build_cli_exploit_settings(
            mode="attack",
            target_ip="10.0.0.50",
            goal=self._goal(),
            config={"exploit": {"permission": "delete-everything-please"}},
        )
        assert settings.permission != ExploitPermission.FULL_ACCESS

    def test_default_config_omitting_permission_is_safe(self):
        """No ``permission`` key at all -> defaults to read_only (safe)."""
        from main import build_cli_exploit_settings
        from tools.exploit_agent import ExploitPermission
        settings = build_cli_exploit_settings(
            mode="attack",
            target_ip="10.0.0.50",
            goal=self._goal(),
            config={"exploit": {}},
        )
        assert settings.permission != ExploitPermission.FULL_ACCESS


class TestRuntimeSkillPromptContext:
    """Runtime skills default to lazy hints instead of full prompt injection."""

    def _selection(self):
        from tools.skill_selector import SkillActivation, SkillSelection

        return SkillSelection(
            activations=(
                SkillActivation(
                    name="scanning-network-with-nmap-advanced",
                    reason="Matched runtime context tag 'nmap'.",
                    source="goal",
                    matched_tags=("nmap", "reconnaissance"),
                    risk_level="advisory",
                    score=30,
                ),
            ),
            prompt_context="### scanning-network-with-nmap-advanced\nFULL SKILL BODY",
        )

    def test_default_uses_lazy_skill_hints_not_full_context(self):
        from main import _apply_runtime_skill_selection
        from tools.exploit_agent import ExploitSettings

        settings = ExploitSettings(target_context={})

        _apply_runtime_skill_selection(
            settings,
            self._selection(),
            config={"skills": {"inject_startup_context": False}},
        )

        assert settings.target_context["skill_context"] == ""
        assert "scanning-network-with-nmap-advanced" in settings.target_context["skill_hints"]
        assert "FULL SKILL BODY" not in settings.target_context["skill_hints"]
        assert settings.target_context["active_skills"][0]["name"] == "scanning-network-with-nmap-advanced"

    def test_opt_in_eager_skill_context_preserves_old_behavior(self):
        from main import _apply_runtime_skill_selection
        from tools.exploit_agent import ExploitSettings

        settings = ExploitSettings(target_context={})

        _apply_runtime_skill_selection(
            settings,
            self._selection(),
            config={"skills": {"inject_startup_context": True}},
        )

        assert "FULL SKILL BODY" in settings.target_context["skill_context"]
        assert "scanning-network-with-nmap-advanced" in settings.target_context["skill_hints"]

# ── M21: --resume restores goal + assessment ───────────────────────────────


class TestResumeStateLoader:
    """M21: ``_load_resume_state`` reloads the saved assessment + chosen goal."""

    def test_loads_assessment_and_chosen_goal(self, tmp_path):
        from main import _load_resume_state
        from tools.goal_suggester import ReconAssessment

        data = {
            "target_ip": "10.0.0.50",
            "os_verdict": "LINUX",
            "os_hints": ["TTL=64"],
            "open_ports": [22],
            "services": [{"port": 22, "service": "ssh", "version": "8.5p1"}],
            "cve_findings": [],
            "overall_risk_score": 40,
            "chosen_goal": "backdoor",
            "chosen_goal_description": "establish persistence",
        }
        (tmp_path / "recon_assessment.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

        args = _make_args(tmp_path)
        result = _load_resume_state(tmp_path, args)
        assert result is not None
        assessment, goal_name, goal_desc = result
        assert isinstance(assessment, ReconAssessment)
        assert assessment.target_ip == "10.0.0.50"
        assert assessment.os_verdict == "LINUX"
        assert goal_name == "backdoor"
        assert goal_desc == "establish persistence"

    def test_returns_none_when_file_missing(self, tmp_path):
        from main import _load_resume_state
        args = _make_args(tmp_path)
        assert _load_resume_state(tmp_path, args) is None

    def test_returns_none_on_corrupt_json(self, tmp_path):
        from main import _load_resume_state
        (tmp_path / "recon_assessment.json").write_text(
            "{not valid json", encoding="utf-8"
        )
        args = _make_args(tmp_path)
        assert _load_resume_state(tmp_path, args) is None

    def test_falls_back_to_args_goal_when_chosen_goal_absent(self, tmp_path):
        """A run started without recon-first has no chosen_goal saved; the
        loader falls back to args.goal so resume still has a goal to restore."""
        from main import _load_resume_state
        data = {
            "target_ip": "10.0.0.50",
            "os_verdict": "UNKNOWN",
            "os_hints": [],
            "open_ports": [],
            "services": [],
            "cve_findings": [],
            "overall_risk_score": 0,
        }
        (tmp_path / "recon_assessment.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        args = _make_args(tmp_path, goal="initial_access", custom_goal="custom obj")
        result = _load_resume_state(tmp_path, args)
        assert result is not None
        _assessment, goal_name, goal_desc = result
        assert goal_name == "initial_access"
        assert goal_desc == "custom obj"


class TestResumeRestoresInAsyncMain:
    """M21 end-to-end: a successful --resume loads recon_assessment.json and
    overrides the goal/assessment, and recon-first is skipped."""

    def test_resume_overrides_goal_and_skips_recon_first(
        self, monkeypatch, tmp_path
    ):
        import main as main_mod

        # Pre-create the reports dir with a run subdir to resume into, plus a
        # saved recon_assessment.json carrying a chosen_goal.
        run_dir = tmp_path / "reports" / "20240101_000000"
        run_dir.mkdir(parents=True)
        (run_dir / "session_state.json").write_text(
            json.dumps({"session_id": "20240101_000000"}), encoding="utf-8"
        )
        assessment_data = {
            "target_ip": "10.0.0.50",
            "os_verdict": "LINUX",
            "os_hints": [],
            "open_ports": [22],
            "services": [],
            "cve_findings": [],
            "overall_risk_score": 10,
            "chosen_goal": "backdoor",
            "chosen_goal_description": "establish persistence",
        }
        (run_dir / "recon_assessment.json").write_text(
            json.dumps(assessment_data), encoding="utf-8"
        )

        # Stub the router so we never touch Ollama.
        class _StubRouter:
            def __init__(self, *a, **kw):
                self._clients = {"glm": object()}
            def get_client(self, name):
                return object()
        monkeypatch.setattr(main_mod, "build_router", lambda *a, **kw: _StubRouter())

        # Use the real GoalEngine so the resume override path exercises it, but
        # force the resolved goal to come from the saved chosen_goal. The real
        # GoalEngine.get("backdoor", ...) returns the backdoor preset.
        # Stub run_exploit_session so we never open an MCP server.
        captured: dict = {}

        async def _fake_session(**kwargs):
            captured["assessment"] = kwargs.get("assessment")
            captured["exploit_settings"] = kwargs.get("exploit_settings")
            return {
                "target_ip": "10.0.0.50",
                "total_actions": 0,
                "workspace": str(kwargs.get("reports_dir")),
                "audit_path": "audit.jsonl",
                "records": [],
                "messages": [],
            }
        monkeypatch.setattr(main_mod, "run_exploit_session", _fake_session)

        # Skip the confirm gate.
        monkeypatch.setattr(
            main_mod.ui, "ask_confirm", AsyncMock(return_value=True), raising=False
        )

        args = _make_args(
            tmp_path,
            mode="attack",
            goal="recon_only",  # a preset so goal resolution doesn't prompt;
                                # the resume override below replaces it with
                                # the saved chosen_goal ("backdoor").
            resume="20240101_000000",
            recon_first=None,  # let the resume path force it False
        )
        args.reports_dir = tmp_path / "reports"

        result = asyncio.run(main_mod.async_main(args))
        assert result == 0, f"async_main returned {result}"

        # recon-first was skipped: the saved assessment was passed through to
        # run_exploit_session (not None as the old ``assessment if recon_first``
        # expression would have yielded on a resumed run).
        assert captured["assessment"] is not None, (
            "resumed run did not pass the saved assessment to run_exploit_session"
        )
        assert captured["assessment"].target_ip == "10.0.0.50"
        # The goal was overridden to the saved chosen_goal ("backdoor"), which
        # the real GoalEngine resolves to the backdoor preset.
        assert captured["exploit_settings"].target_context["goal"] == "backdoor"


# ── M20: --swarm dispatches on mode ───────────────────────────────────────


class TestSwarmModeRouting:
    """M20: attack mode awaits ``run_autonomous_campaign``; recon mode runs the
    synchronous loop via ``asyncio.to_thread``."""

    def _install_fake_agent_loop(self, monkeypatch):
        """Install a fake AgentLoop that records which entrypoint was used."""
        import agent_loop as al_mod

        instances: list = []

        class _FakeAgentLoop:
            def __init__(self, **kwargs):
                self.run_autonomous_campaign = AsyncMock(
                    return_value={"tasks_completed": 1, "tasks_blocked": 0,
                                  "tasks_failed": 0, "findings_report_ready": 0}
                )
                self.run = MagicMock(return_value={
                    "tasks_completed": 2, "tasks_blocked": 0,
                    "tasks_failed": 0, "findings_report_ready": 0,
                })
                instances.append(self)

        monkeypatch.setattr(al_mod, "AgentLoop", _FakeAgentLoop)
        return instances

    def _stub_common(self, monkeypatch, tmp_path):
        import main as main_mod

        class _StubRouter:
            def __init__(self, *a, **kw):
                self._clients = {"glm": object()}
            def get_client(self, name):
                return object()
        monkeypatch.setattr(main_mod, "build_router", lambda *a, **kw: _StubRouter())

        async def _fake_session(**kwargs):
            return {
                "target_ip": "10.0.0.50",
                "total_actions": 0,
                "workspace": str(kwargs.get("reports_dir")),
                "audit_path": "audit.jsonl",
                "records": [],
                "messages": [],
            }
        monkeypatch.setattr(main_mod, "run_exploit_session", _fake_session)
        monkeypatch.setattr(
            main_mod.ui, "ask_confirm", AsyncMock(return_value=True), raising=False
        )

    def test_attack_mode_calls_run_autonomous_campaign(self, monkeypatch, tmp_path):
        import main as main_mod

        instances = self._install_fake_agent_loop(monkeypatch)
        self._stub_common(monkeypatch, tmp_path)

        args = _make_args(
            tmp_path,
            mode="attack",
            custom_goal="compromise the target",
            swarm=True,
        )
        result = asyncio.run(main_mod.async_main(args))
        assert result == 0, f"async_main returned {result}"

        assert len(instances) == 1, "AgentLoop should be constructed once"
        loop = instances[0]
        loop.run_autonomous_campaign.assert_awaited_once()
        # attack mode must NOT take the to_thread(swarm_loop.run) path
        loop.run.assert_not_called()

    def test_recon_mode_calls_sync_run_in_thread(self, monkeypatch, tmp_path):
        import main as main_mod

        instances = self._install_fake_agent_loop(monkeypatch)
        self._stub_common(monkeypatch, tmp_path)

        args = _make_args(
            tmp_path,
            mode="recon",
            custom_goal="map the target",
            swarm=True,
        )
        result = asyncio.run(main_mod.async_main(args))
        assert result == 0, f"async_main returned {result}"

        assert len(instances) == 1
        loop = instances[0]
        # recon mode runs the synchronous loop (via asyncio.to_thread), so
        # ``run`` is called and ``run_autonomous_campaign`` is not awaited.
        loop.run.assert_called_once()
        loop.run_autonomous_campaign.assert_not_awaited()
