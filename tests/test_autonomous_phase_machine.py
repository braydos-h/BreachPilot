"""Regression tests for campaign dispatch and evidence-gated state.

The autonomous orchestrator's ``AttackModuleExecutor.execute`` historically
treated a module's ``suggested_command`` / ``script`` keys as dead data: it
counted a ``script_generated`` module as succeeded but never DISPATCHED the
artifact, so ``record_success`` never saw a ``shell_type`` and
``access_achieved`` stayed False. The downstream ``_phase_privilege_escalation``
and ``_phase_lateral_movement`` are gated on ``access_achieved`` /
``pivot_targets`` at the call site (``_attack_target`` :857-862), so they
never ran for script-generating modules.

Phase 2.1 wires an optional ``tool_executor`` into ``AttackModuleExecutor`` so
a module's runnable artifact is dispatched. Raw worker output is not
target-bound proof, so shell and credential markers must not promote access.
These tests pin that:

1. A shell-shaped worker result does not flip ``access_achieved`` or set
   ``shell_type``.
2. An info-stub module (status=info, suggested_command only) does NOT falsely
   set ``access_achieved`` -- dispatch is skipped for status=info.
3. Credential-shaped worker output does not populate trusted credentials.
4. A script-generated module whose dispatch output signals failure is marked
   FAILED (not silently succeeded), so the retry loop can re-attempt it.
5. Raw module or worker claims cannot unlock privilege escalation.
6. A nested ``BaseExceptionGroup`` from dispatch is contained and logged.
"""

from __future__ import annotations

import asyncio
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import tools.autonomous_orchestrator as orch_mod
import tools.campaign.executor as campaign_executor_mod
from tools.attack_modules import AttackModule, ModuleContext
from tools.attack_modules.base import ModuleResult
from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
    TaskStatus,
    observe_autonomous_progress,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo


@pytest.fixture(autouse=True)
def _patch_get_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the executor's ``get_module`` lookup resolve the fake test modules
    by name. ``get_module`` is imported into the orchestrator module's
    namespace, so patch the symbol there (not the registry)."""
    monkeypatch.setattr(orch_mod, "get_module", _fake_get_module)


# ── Fake modules ────────────────────────────────────────────────────────────


class _ShellCompromiseModule(AttackModule):
    """Returns a script; the fake tool_executor will emit an unverified claim."""

    name = "_ShellCompromise"
    description = "test module that reports a shell-shaped worker result"
    target_services = ["http"]
    target_ports = [80]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('meterpreter session 1 opened')",
            "note": "Generates a meterpreter payload script.",
        }


class _InfoStubModule(AttackModule):
    """status=info with only a suggested_command -- must NOT be dispatched."""

    name = "_InfoStub"
    description = "info-stub module with suggested_command only"
    target_services = ["http"]
    target_ports = [80]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Use sqlmap for SQL injection testing.",
            "suggested_command": "sqlmap -u 'http://10.0.0.5/' --batch",
        }


class _CredDumpModule(AttackModule):
    """Returns a script; the fake tool_executor emits a credential dump."""

    name = "_CredDump"
    description = "module that dumps credentials"
    target_services = ["smb"]
    target_ports = [445]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "success",
            "module": self.name,
            "script": "print('dumping hashes ... SAM dumped')",
        }


class _SelfReportedCompromiseModule(AttackModule):
    """A plugin-shaped result that claims proof fields without verification."""

    name = "_SelfReportedCompromise"
    description = "test module that supplies untrusted compromise fields"
    target_services = ["http"]
    target_ports = [80]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "success",
            "module": self.name,
            "shell_type": "meterpreter",
            "privilege_level": "root",
            "credentials": [{"username": "admin", "password": "claimed"}],
            "pivot_targets": ["10.0.0.99"],
            "success": True,
            "verified_success": True,
            "verdict": "confirmed",
        }


class _NoCompromiseModule(AttackModule):
    """Returns a script; the fake tool_executor emits 'exploit failed'."""

    name = "_NoCompromise"
    description = "module whose dispatch fails"
    target_services = ["http"]
    target_ports = [80]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('exploit failed: no session created')",
        }


class _PivotModule(AttackModule):
    """Returns a script; the fake tool_executor emits a shell + pivot target."""

    name = "_Pivot"
    description = "module that yields a shell and a pivot target"
    target_services = ["http"]
    target_ports = [80]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('meterpreter session 1 opened ; pivot 10.0.0.99')",
        }


_FAKE_MODULES: dict[str, AttackModule] = {
    "_ShellCompromise": _ShellCompromiseModule(),
    "_InfoStub": _InfoStubModule(),
    "_CredDump": _CredDumpModule(),
    "_SelfReportedCompromise": _SelfReportedCompromiseModule(),
    "_NoCompromise": _NoCompromiseModule(),
    "_Pivot": _PivotModule(),
}


# ── Fakes ───────────────────────────────────────────────────────────────────


@dataclass
class _ScopeResult:
    allowed: bool
    reason: str = ""


class _AllowScopeGate:
    """A permissive scope gate -- the executor's scope check must pass for the
    module dispatch path to be exercised (the target-IP lock is enforced at the
    MCP tool layer in production, not here)."""

    def check_scope(self, *, asset, action_type=None, tool_name=None, risk_level=None):
        return _ScopeResult(allowed=True, reason="test-allow")


def _fake_get_module(name: str) -> AttackModule | None:
    return _FAKE_MODULES.get(name)


def _fake_find_modules(ctx: ModuleContext) -> list[tuple[int, AttackModule]]:
    # Return every fake module with a non-zero score so _phase_exploitation
    # creates tasks for them.
    return [(50, m) for m in _FAKE_MODULES.values()]


def _recon_with_http() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.5",
        os_family="linux",
        services=[ServiceInfo(port=80, protocol="tcp", service="http")],
        open_ports=[80],
    )


def _timeline_types(state: AttackState) -> list[str]:
    return [e["event_type"] for e in state.timeline]


def _executor(
    tmp_path: Path,
    *,
    tool_executor=None,
    scope_gate: Any | None = None,
) -> AttackModuleExecutor:
    return AttackModuleExecutor(
        scope_gate=scope_gate or _AllowScopeGate(),
        risk_controller=None,
        evidence_store=None,
        tool_executor=tool_executor,
    )


def _task(module_name: str, target: str = "10.0.0.5") -> AttackTask:
    return AttackTask(
        task_id="ATK-TEST",
        phase=AttackPhase.EXPLOITATION,
        module_name=module_name,
        target=target,
        aggression=AggressionLevel.NORMAL,
        priority=50,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("script_source", ["module_result", "generator"])
async def test_campaign_script_write_does_not_follow_workspace_modules_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script_source: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "modules").symlink_to(outside, target_is_directory=True)

    script = "print('safe generated script')\n"
    module = _ShellCompromiseModule()
    module.generate_python_script = lambda _ctx: script
    mresult = ModuleResult(status="script_generated", script=script if script_source == "module_result" else "")
    commands: list[str] = []

    def fake_executor(command: str, _ctx: dict[str, Any]) -> str:
        commands.append(command)
        return "ordinary output"

    executor = _executor(tmp_path, tool_executor=fake_executor)
    monkeypatch.setattr(executor, "_dispatch_block_reason", lambda _command, _task: None)
    ctx = ModuleContext(target_ip="10.0.0.5", workspace=workspace)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    dispatched = await executor._dispatch_module_artifact(module, mresult, ctx, _task(module.name), state)

    assert dispatched is not None
    argv = shlex.split(commands[0])
    assert argv[0] == "python"
    saved_path = Path(argv[1])
    assert saved_path.parent == workspace
    assert saved_path.read_text(encoding="utf-8") == script
    assert list(outside.iterdir()) == []
    assert (workspace / "modules").is_symlink()


# ── 1. Worker shell markers do not set access_achieved ──────────────────────


@pytest.mark.asyncio
async def test_shell_marker_output_does_not_set_access(tmp_path: Path) -> None:
    """A sandbox worker's meterpreter/id text is not proof of target access."""
    captured: list[str] = []

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        captured.append(cmd)
        return "meterpreter session 1 opened ; uid=0(root)"

    ex = _executor(tmp_path, tool_executor=_exec)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_ShellCompromise"), state)

    assert out["success"] is False
    assert out["verified_success"] is False
    assert out["completed"] is True
    assert state.access_achieved is False
    assert state.shell_type == ""
    assert state.privilege_level == "none"
    assert state.successful_exploits == []
    assert state.failed_attempts == {}
    assert captured, "the module's script must have been dispatched"
    assert "compromise_verified" not in _timeline_types(state)


@pytest.mark.asyncio
async def test_plugin_supplied_proof_fields_do_not_mutate_campaign_state(tmp_path: Path) -> None:
    ex = _executor(tmp_path, tool_executor=None)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())
    task = _task("_SelfReportedCompromise")

    out = await ex.execute(task, state)

    assert out["success"] is False
    assert out["verified_success"] is False
    assert out["completed"] is True
    assert task.status == TaskStatus.COMPLETED
    assert state.access_achieved is False
    assert state.shell_type == ""
    assert state.privilege_level == "none"
    assert state.credentials_found == []
    assert state.pivot_targets == []
    assert state.successful_exploits == []
    assert out["result"]["verified_success"] is False
    assert not {"shell_type", "credentials", "pivot_targets", "verdict", "success"} & out["result"].keys()


@pytest.mark.asyncio
async def test_dispatch_keeps_loop_responsive_and_reports_monotonic_actions(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    progress: list[dict[str, Any]] = []
    dispatch_started_at = 0.0

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        nonlocal dispatch_started_at
        dispatch_started_at = time.monotonic()
        started.set()
        release.wait(1.0)
        return "exploit failed: no session created"

    ex = _executor(tmp_path, tool_executor=_exec)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    with observe_autonomous_progress(progress.append):
        first = asyncio.create_task(ex.execute(_task("_NoCompromise"), state))
        assert await asyncio.to_thread(started.wait, 2.0)
        assert time.monotonic() - dispatch_started_at < 0.5, "tool dispatch blocked the API event loop"
        release.set()
        await first
        await ex.execute(_task("_InfoStub"), state)

    assert [item["action"] for item in progress if "action" in item] == [1, 2]


# ── 2. Info-stub does NOT set access_achieved ───────────────────────────────


@pytest.mark.asyncio
async def test_info_stub_does_not_set_access(tmp_path: Path) -> None:
    """status=info with only a suggested_command must skip dispatch entirely --
    no shell_type, no access_achieved, no false foothold.

    Phase 1: info-stubs no longer count as succeeded either -- they produce no
    runnable artifact and no compromise signal, so the retry loop must re-queue
    them. The module's suggested_command is dead data until the recipe emits a
    dispatchable status (script_generated/success). This test encodes the
    corrected behavior; pre-Phase-1 it asserted success=True (the silent
    false-positive this fix removes).
    """
    captured: list[str] = []

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        captured.append(cmd)
        return "meterpreter session 1"  # would falsely compromise if dispatched

    ex = _executor(tmp_path, tool_executor=_exec)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_InfoStub"), state)

    assert out["success"] is False, "info-stubs must NOT count as succeeded (no artifact, no compromise)"
    assert state.access_achieved is False, "info-stub must NOT set access_achieved"
    assert state.shell_type == ""
    assert captured == [], "info-stub's suggested_command must NOT be dispatched"


# ── 3. Credential dump populates credentials_found ──────────────────────────


@pytest.mark.asyncio
async def test_credential_marker_output_does_not_populate_credentials(tmp_path: Path) -> None:
    """Credential-shaped worker text is not proof that target creds were read."""

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        return "dumping hashes ... SAM dumped ; ntlm hashes: admin:8846F7EAEE8FB117"

    ex = _executor(tmp_path, tool_executor=_exec)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_CredDump"), state)

    assert out["success"] is False
    assert out["completed"] is True
    assert state.access_achieved is False, "cred dump is not a shell compromise"
    assert state.credentials_found == []
    assert state.successful_exploits == []
    assert "cred_dump_verified" not in _timeline_types(state)


# ── 4. Dispatch failure marks the module FAILED ─────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_failure_marks_module_failed(tmp_path: Path) -> None:
    """A script-generated module whose dispatch output carries an explicit
    failure marker ('exploit failed', 'no session created') must be marked
    FAILED so the retry loop can re-attempt it -- NOT silently succeeded."""

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        return "exploit failed: no session created"

    ex = _executor(tmp_path, tool_executor=_exec)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_NoCompromise"), state)

    assert out["success"] is False, "dispatch failure must NOT be a success"
    assert out["completed"] is False
    assert state.access_achieved is False
    assert "_NoCompromise" in state.failed_attempts, "failure must be recorded for retry"
    assert "dispatch_failure" in _timeline_types(state)


@pytest.mark.asyncio
async def test_dispatch_exception_group_is_contained_and_nested_errors_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logged: list[BaseException] = []
    monkeypatch.setattr(campaign_executor_mod, "_log_nested_exceptions", logged.append)

    def _raise_group(_command: str, _ctx: dict[str, Any]) -> str:
        raise BaseExceptionGroup("worker failed", [KeyboardInterrupt("worker interrupted")])

    ex = _executor(tmp_path, tool_executor=_raise_group)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_ShellCompromise"), state)

    assert out["success"] is False
    assert out["completed"] is False
    assert state.access_achieved is False
    assert len(logged) == 1
    assert isinstance(logged[0], BaseExceptionGroup)
    assert "dispatch_err" in _timeline_types(state)


# ── 5. No tool_executor -> generated artifact remains unverified ────────────


@pytest.mark.asyncio
async def test_no_tool_executor_keeps_generated_artifact_unverified(tmp_path: Path) -> None:
    """Generating an artifact without dispatch completes generation only; it
    cannot count as a successful exploit or promote campaign access."""
    ex = _executor(tmp_path, tool_executor=None)
    state = AttackState(target="10.0.0.5", recon_result=_recon_with_http())

    out = await ex.execute(_task("_ShellCompromise"), state)

    assert out["success"] is False
    assert out["verified_success"] is False
    assert out["completed"] is True
    assert state.successful_exploits == []
    assert state.access_achieved is False, "no dispatch -> no shell verification -> no access"
    # The module's own dict keys survive the round-trip.
    assert out["result"].get("script") == "print('meterpreter session 1 opened')"


# ── 6. ModuleResult adapter round-trip ──────────────────────────────────────


def test_module_result_to_result_round_trip() -> None:
    """ModuleResult.to_result adapts a legacy dict (with 'credentials' as a
    list[dict]) into the typed shape; to_dict() re-emits the dict keys the
    renderer and record_success expect."""
    legacy = {
        "status": "success",
        "module": "X",
        "note": "n",
        "suggested_command": "cmd",
        "script": "s",
        "credentials": [{"user": "admin", "password": "pw"}],
        "techniques": ["union"],  # pass-through extra key
    }
    mr = ModuleResult.to_result(legacy)
    assert mr.status == "success"
    assert mr.suggested_command == "cmd"
    assert mr.credentials_found == ["user=admin password=pw"]
    assert mr.extra["techniques"] == ["union"]

    d = mr.to_dict()
    assert d["status"] == "success"
    assert d["suggested_command"] == "cmd"
    assert d["credentials"] == ["user=admin password=pw"]
    # Pass-through extra key surfaces at top level.
    assert d["techniques"] == ["union"]


def test_module_result_non_dict_degrades_safely() -> None:
    mr = ModuleResult.to_result("not a dict")  # type: ignore[arg-type]
    assert mr.status == "info"
    assert mr.note.startswith("non-dict")


# ── 7. _phase_privilege_escalation runs after access ────────────────────────


@pytest.mark.asyncio
async def test_phase_privilege_escalation_skips_unverified_shell_text(tmp_path: Path) -> None:
    """Raw worker output cannot unlock privilege escalation against a target."""

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        return "meterpreter session 1 opened"  # no uid=0 -> privilege_level stays ""

    orch = AutonomousOrchestrator(
        mission_config={"max_cycles": 5},
        workspace_root=tmp_path,
        tool_executor=_exec,
        scope_gate=_AllowScopeGate(),
    )
    orch._phase_reconnaissance = _async_noop  # type: ignore[assignment]
    # Stub _phase_exploitation to run the module through the executor.
    privesc_called = {"v": False}

    async def _fake_exploit(state: AttackState) -> None:
        task = _task("_ShellCompromise", state.target)
        await orch._executor.execute(task, state)

    async def _fake_privesc(state: AttackState) -> None:
        privesc_called["v"] = True
        state.add_timeline_event("phase_start", "Privilege escalation phase started")

    async def _fake_validation(state: AttackState) -> None:
        pass

    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]
    orch._phase_validation = _fake_validation  # type: ignore[assignment]
    # Pre-seed recon_result so _attack_target's no-attack-surface guard passes.
    state = orch.get_state("10.0.0.5")
    state.recon_result = _recon_with_http()

    result = await orch._attack_target("10.0.0.5")

    assert result["status"] == "complete"
    state = orch.get_state("10.0.0.5")
    assert state.access_achieved is False
    assert privesc_called["v"] is False


@pytest.mark.asyncio
async def test_phase_privilege_escalation_skipped_without_access(tmp_path: Path) -> None:
    """When access_achieved stays False (info-stub module only), the privesc
    call-site gate must skip ``_phase_privilege_escalation`` -- the pre-Phase-2
    behavior was to always skip; Phase 2 must not regress that."""

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        return "meterpreter session 1"

    orch = AutonomousOrchestrator(
        mission_config={"max_cycles": 5},
        workspace_root=tmp_path,
        tool_executor=_exec,
        scope_gate=_AllowScopeGate(),
    )
    privesc_called = {"v": False}

    async def _fake_exploit(state: AttackState) -> None:
        # Run the info-stub -- dispatch is skipped, access_achieved stays False.
        task = _task("_InfoStub", state.target)
        await orch._executor.execute(task, state)

    async def _fake_privesc(state: AttackState) -> None:
        privesc_called["v"] = True

    async def _fake_validation(state: AttackState) -> None:
        pass

    orch._phase_reconnaissance = _async_noop  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]
    orch._phase_validation = _fake_validation  # type: ignore[assignment]
    state = orch.get_state("10.0.0.5")
    state.recon_result = _recon_with_http()

    await orch._attack_target("10.0.0.5")

    state = orch.get_state("10.0.0.5")
    assert state.access_achieved is False, "info-stub must not flip access_achieved"
    assert privesc_called["v"] is False, "privesc must NOT run without access"


# ── 8. _phase_lateral_movement runs with pivot_targets ──────────────────────


@pytest.mark.asyncio
async def test_phase_lateral_movement_runs_with_pivot_targets(tmp_path: Path) -> None:
    """When ``state.pivot_targets`` is populated, ``_attack_target`` :861 fires
    ``_phase_lateral_movement``. Uses the remote-target path (no local
    short-circuit) and a real LateralMovement task creation."""
    orch = AutonomousOrchestrator(
        mission_config={"max_cycles": 5, "max_pivot_depth": 2},
        workspace_root=tmp_path,
        scope_gate=_AllowScopeGate(),
    )

    async def _fake_recon(state: AttackState) -> None:
        state.recon_result = _recon_with_http()

    async def _fake_exploit(state: AttackState) -> None:
        state.access_achieved = True
        state.pivot_targets.append("10.0.0.99")

    async def _fake_privesc(state: AttackState) -> None:
        state.privilege_level = "root"  # maxed -> lateral gate still fires on pivot_targets

    async def _fake_validation(state: AttackState) -> None:
        pass

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]
    orch._phase_validation = _fake_validation  # type: ignore[assignment]

    result = await orch._attack_target("10.0.0.5")

    assert result["status"] == "complete"
    state = orch.get_state("10.0.0.5")
    # A lateral-movement task targeting the pivot must have been created.
    lateral_tasks = [
        t for t in orch._tasks.values() if t.phase == AttackPhase.LATERAL_MOVEMENT and t.target == "10.0.0.99"
    ]
    assert lateral_tasks, "lateral phase must create a pivot task when pivot_targets is set"
    assert "phase_start" in _timeline_types(state)


# ── helpers ─────────────────────────────────────────────────────────────────


async def _async_noop(state: AttackState) -> None:  # noqa: D401
    """Async no-op phase stand-in."""
    return None
