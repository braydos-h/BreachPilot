"""Autonomous campaign MCP tools (split from god file)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.attack_modules import ModuleContext
from tools.autonomous_orchestrator import AggressionLevel, AutonomousOrchestrator, TaskStatus
from tools.autonomous_orchestrator import AttackPhase as OrchAttackPhase
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.mcp_shared import check_targets_allowlist
from tools.mcp_tools.registry import ToolContext
from tools.validation_utils import is_fqdn, resolve_target_to_ip, validate_target_or_ip

# Strong references to background campaign tasks. CPython's event loop holds
# only a weak ref to a task, so an unreferenced asyncio.create_task() can be
# garbage-collected mid-run and the campaign's final/error state.json is never
# written (leaving it permanently "running"). The done-callback drops the ref
# once the task finishes so completed campaigns don't leak.
_running_campaign_tasks: set = set()

_CAMPAIGN_ID_RE = re.compile(r"campaign-[0-9]{8}_[0-9]{6}-[0-9a-f]{8}(?:-[0-9a-f]{12})?\Z")
_MAX_CAMPAIGN_STATE_BYTES = 4 * 1024 * 1024

# campaign_id -> live AutonomousOrchestrator, so stop_campaign can signal a
# graceful stop. Popped when the background task finishes (see the done
# callback in start_autonomous_campaign).
_campaign_orchestrators: dict[str, Any] = {}


def _valid_campaign_id(campaign_id: str) -> bool:
    return isinstance(campaign_id, str) and bool(_CAMPAIGN_ID_RE.fullmatch(campaign_id))


def _new_campaign_id(target: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    target_hash = hashlib.sha256(target.encode()).hexdigest()[:8]
    return f"campaign-{timestamp}-{target_hash}-{secrets.token_hex(6)}"


def _create_campaign_dir(workspace: Path, campaign_id: str) -> Path:
    """Create a unique campaign directory without following a planted symlink."""
    if not _valid_campaign_id(campaign_id):
        raise ValueError("invalid campaign_id")
    root = workspace.resolve(strict=True)
    campaigns_path = root / "campaigns"
    campaign_path = campaigns_path / campaign_id
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)

    if os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd:
        root_fd = os.open(root, dir_flags | nofollow)
        campaigns_fd: int | None = None
        campaign_fd: int | None = None
        try:
            try:
                os.mkdir("campaigns", mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            campaigns_fd = os.open("campaigns", dir_flags | nofollow, dir_fd=root_fd)
            if not stat.S_ISDIR(os.fstat(campaigns_fd).st_mode):
                raise ValueError("campaigns path is not a directory")
            os.mkdir(campaign_id, mode=0o700, dir_fd=campaigns_fd)
            campaign_fd = os.open(campaign_id, dir_flags | nofollow, dir_fd=campaigns_fd)
            if not stat.S_ISDIR(os.fstat(campaign_fd).st_mode):
                raise ValueError("campaign path is not a directory")
            return campaign_path
        finally:
            if campaign_fd is not None:
                os.close(campaign_fd)
            if campaigns_fd is not None:
                os.close(campaigns_fd)
            os.close(root_fd)

    # Path-based fallback for platforms without descriptor-relative mkdir/open.
    if campaigns_path.exists() or campaigns_path.is_symlink():
        if campaigns_path.is_symlink() or not campaigns_path.is_dir():
            raise ValueError("campaigns path contains a symlink or is not a directory")
        if not campaigns_path.resolve(strict=True).is_relative_to(root):
            raise ValueError("campaigns path escapes the workspace")
    else:
        campaigns_path.mkdir(mode=0o700)
    campaign_path.mkdir(mode=0o700)
    if campaign_path.is_symlink() or not campaign_path.resolve(strict=True).is_relative_to(root):
        raise ValueError("campaign path contains a symlink or escapes the workspace")
    return campaign_path


def _make_sandbox_recon_provider(ctx: ToolContext, config: dict[str, Any] | None, aggression: str):
    """Build the campaign recon callback from the active MCP sandbox context."""

    async def provide(target: str) -> Any:
        from tools.mcp_tools.recon import sandbox_recon_host

        result, error = await sandbox_recon_host(ctx, target, config, aggression=aggression)
        if error:
            raise RuntimeError(error)
        if result is None:
            raise RuntimeError("sandbox recon returned no result")
        return result

    return provide


def _open_campaign_dir(workspace: Path, campaign_id: str) -> tuple[int | None, Path]:
    """Open a campaign directory without following worker-created symlinks.

    The directory descriptor is used for state-file I/O where the platform
    supports descriptor-relative operations. The returned path is only for
    orchestrator configuration; it is constructed from a validated ID.
    """
    if not _valid_campaign_id(campaign_id):
        raise ValueError("invalid campaign_id")

    root = workspace.resolve(strict=True)
    campaigns_path = root / "campaigns"
    campaign_path = campaigns_path / campaign_id
    if campaigns_path.is_symlink() or campaign_path.is_symlink():
        raise ValueError("campaign path contains a symlink")
    resolved_campaign = campaign_path.resolve(strict=True)
    if not resolved_campaign.is_relative_to(root):
        raise ValueError("campaign path escapes the workspace")

    dir_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    root_fd: int | None = None
    campaigns_fd: int | None = None
    campaign_fd: int | None = None
    try:
        root_fd = os.open(root, os.O_RDONLY | dir_flag | nofollow | cloexec)
        if os.open in os.supports_dir_fd:
            campaigns_fd = os.open("campaigns", os.O_RDONLY | dir_flag | nofollow | cloexec, dir_fd=root_fd)
            campaign_fd = os.open(campaign_id, os.O_RDONLY | dir_flag | nofollow | cloexec, dir_fd=campaigns_fd)
            if not stat.S_ISDIR(os.fstat(campaign_fd).st_mode):
                raise ValueError("campaign path is not a directory")
            return campaign_fd, resolved_campaign
        # Windows does not provide dir_fd for these calls. Reject static
        # symlinks and verify containment before using the path-based fallback.
        if campaigns_path.resolve(strict=True) != campaigns_path:
            raise ValueError("campaign path contains a symlink")
        return None, resolved_campaign
    except BaseException:
        if campaign_fd is not None:
            os.close(campaign_fd)
        raise
    finally:
        if campaigns_fd is not None:
            os.close(campaigns_fd)
        if root_fd is not None:
            os.close(root_fd)


def _read_campaign_state(workspace: Path, campaign_id: str) -> tuple[Path, dict[str, Any]]:
    """Read a regular campaign state file without following symlinks."""
    campaign_fd, campaign_path = _open_campaign_dir(workspace, campaign_id)
    state_path = campaign_path / "state.json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    state_fd: int | None = None
    try:
        if campaign_fd is not None:
            state_fd = os.open("state.json", flags, dir_fd=campaign_fd)
        else:
            if state_path.is_symlink() or not state_path.resolve(strict=True).is_relative_to(campaign_path):
                raise ValueError("campaign state path contains a symlink or escapes the campaign")
            state_fd = os.open(state_path, flags)
        if not stat.S_ISREG(os.fstat(state_fd).st_mode):
            raise ValueError("campaign state is not a regular file")
        chunks: list[bytes] = []
        remaining = _MAX_CAMPAIGN_STATE_BYTES + 1
        while remaining > 0:
            chunk = os.read(state_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_CAMPAIGN_STATE_BYTES:
            raise ValueError("campaign state exceeds the size limit")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("campaign state must be a JSON object")
        return campaign_path, data
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if campaign_fd is not None:
            os.close(campaign_fd)


def _write_campaign_state(workspace: Path, campaign_id: str, state_data: dict[str, Any]) -> None:
    """Atomically replace state.json relative to a pinned campaign directory."""
    campaign_fd, campaign_path = _open_campaign_dir(workspace, campaign_id)
    state_path = campaign_path / "state.json"
    payload = json.dumps(state_data, indent=2, default=str).encode("utf-8")
    temp_name = f".state.json.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    temp_fd: int | None = None
    try:
        if campaign_fd is not None:
            try:
                state_stat = os.stat("state.json", dir_fd=campaign_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(state_stat.st_mode):
                    raise ValueError("campaign state is not a regular file")
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=campaign_fd)
        else:
            try:
                state_info = state_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISLNK(state_info.st_mode) or not state_path.resolve(strict=True).is_relative_to(
                    campaign_path
                ):
                    raise ValueError("campaign state path contains a symlink or escapes the campaign")
                if not stat.S_ISREG(state_info.st_mode):
                    raise ValueError("campaign state is not a regular file")
            temp_fd = os.open(state_path.with_name(temp_name), flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short write to campaign state")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        if campaign_fd is not None:
            os.replace(temp_name, "state.json", src_dir_fd=campaign_fd, dst_dir_fd=campaign_fd)
            os.fsync(campaign_fd)
        else:
            os.replace(state_path.with_name(temp_name), state_path)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if campaign_fd is not None:
            os.close(campaign_fd)


def _compromised_hosts_for_state(state: Any) -> list[str]:
    """Return verified target hosts, never module names or self-reported status."""
    if not (getattr(state, "access_achieved", False) or getattr(state, "credentials_found", [])):
        return []
    host = str(getattr(state, "resolved_ip", "") or getattr(state, "target", "") or "").strip()
    return [host] if host else []


def _record_campaign_step_result(state: Any, state_data: dict[str, Any], status: str) -> None:
    """Persist operational completion separately from verified compromise."""
    tasks = state_data.get("tasks", {})
    counter = "completed" if status in ("success", "exploited", "script_generated") else "failed"
    tasks[counter] = tasks.get(counter, 0) + 1
    state_data["tasks"] = tasks
    state_data["compromised_hosts"] = _compromised_hosts_for_state(state)


def register_campaign_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    async def start_autonomous_campaign(
        target_ip: str, goal: str = "initial_access", aggression_level: str = "normal"
    ) -> str:
        """Start a fully autonomous attack campaign against a target IP.

        Launches the AutonomousOrchestrator in a background daemon thread. The orchestrator
        runs the full kill chain: reconnaissance → enumeration → exploitation →
        privilege escalation → lateral movement → persistence. Campaign state is
        periodically saved to the workspace for monitoring via get_campaign_status.

        Args:
            target_ip: IPv4 address of the target host.
            goal: Campaign goal — 'initial_access', 'privilege_escalation', 'full_compromise',
                  or 'lateral_movement'.
            aggression_level: 'stealth', 'normal', 'aggressive', or 'maximum'.

        Returns:
            campaign_id, status 'started', and the campaign directory path.

        Example:
            start_autonomous_campaign("192.168.1.100", "full_compromise", "aggressive")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        # Check config gate
        swarm_cfg = (config or {}).get("swarm", {})
        if not swarm_cfg.get("enabled", True):
            return "BLOCKED: swarm is disabled in config.yaml."

        try:
            aggression_map: dict[str, AggressionLevel] = {
                "stealth": AggressionLevel.STEALTH,
                "normal": AggressionLevel.NORMAL,
                "aggressive": AggressionLevel.AGGRESSIVE,
                "maximum": AggressionLevel.MAXIMUM,
            }
            agg = aggression_map.get(aggression_level.lower(), AggressionLevel.NORMAL)

            campaign_id = _new_campaign_id(target_ip)
            campaign_dir = _create_campaign_dir(workspace, campaign_id)

            # Build mission config. The ``autonomous`` block (config.yaml) is
            # merged first so its opt-in Phase 2 flags (persistence_phase,
            # checkpoint_every, adaptive_replan, max_pivot_depth) reach the
            # orchestrator; the explicit keys below then override the shared
            # ones (target/goal/aggression/max_cycles/workspace).
            mission_config = {
                **(config or {}).get("autonomous", {}),
                # Phase 6.2: pass the opsec block through so the orchestrator's
                # AttackModuleExecutor can build an OpsecManager and make
                # AggressionLevel.STEALTH pacing load-bearing. Absent -> {} ->
                # disabled profile -> pacing no-op (legacy behavior).
                "opsec": (config or {}).get("opsec", {}),
                # Phase 3: pass the MSF auto-local_exploit_suggester flag through
                # so the privesc phase can dispatch the advisory follow-up.
                "msf_auto_les": (config or {})
                .get("exploit", {})
                .get("msf", {})
                .get("auto_local_exploit_suggester", False),
                # D1: pass the orchestrator.semantic_memory flag + ollama/embed
                # config through so the orchestrator can build its own
                # SemanticMemoryManager when no manager is supplied directly.
                # Default false (opt-in per the new-attack-path rule).
                "semantic_memory": bool((config or {}).get("orchestrator", {}).get("semantic_memory", False)),
                "ollama": (config or {}).get("ollama", {}),
                "embedding_model": (config or {}).get("memory", {}).get("embedding_model", "nomic-embed-text"),
                # §23: the agent block rides along so the campaign retry cap
                # (agent.max_retries_per_task) reaches the orchestrator.
                "agent": (config or {}).get("agent", {}),
                # Kill-chain state machine (design §killchain): pass the block
                # through so the orchestrator's edge-preference branch can be
                # enabled. Default off (opt-in per the new-attack-path rule).
                "killchain": (config or {}).get("killchain", {}),
                # Snapshot/rollback (design §snapshots): pass the blocks through
                # so the executor's snapshot-before-destructive hook and the
                # counterfactual toggle reach the Path-B dispatch funnel.
                # Default off (opt-in per the new-attack-path rule).
                "snapshots": (config or {}).get("snapshots", {}),
                "replay_simulator": (config or {}).get("replay_simulator", {}),
                "target": target_ip,
                "goal": goal,
                "aggression": agg.value,
                "max_cycles": (config or {}).get("exploit", {}).get("max_rounds", 50),
                "max_aggression": agg.value,
                "workspace": str(campaign_dir),
            }

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=campaign_dir,
                sandbox_recon_provider=_make_sandbox_recon_provider(ctx, config, agg.value),
                require_sandbox_recon=True,
            )

            # Domain targeting: when the operator passed a domain (not an IP)
            # to start_autonomous_campaign, resolve it and thread both the
            # original domain and the resolved IP into the orchestrator so
            # the Path-B subdomain-expansion branch in _phase_reconnaissance
            # fires. IP-only campaigns pass "" (unchanged behavior).
            _orig_target = ""
            _resolved_ip = ""
            if is_fqdn(target_ip):
                _orig_target = target_ip
                _resolved_ip = resolve_target_to_ip(target_ip) or ""

            # Write initial state
            state = orchestrator.get_state(target_ip)
            if _orig_target:
                state.original_target = _orig_target
            if _resolved_ip:
                state.resolved_ip = _resolved_ip
            state.aggression = agg
            state.add_timeline_event("campaign_start", f"Autonomous campaign started with goal: {goal}")

            initial_state = {
                "campaign_id": campaign_id,
                "target": target_ip,
                "goal": goal,
                "aggression": agg.value,
                "status": "started",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "current_phase": state.current_phase.value,
                "tasks": {"completed": 0, "failed": 0, "pending": 0},
                "compromised_hosts": [],
                "last_error": "",
            }
            _write_campaign_state(workspace, campaign_id, initial_state)

            # Launch in background asyncio task
            async def _run_campaign() -> None:
                try:
                    await orchestrator.run_autonomous_campaign(
                        [target_ip],
                        original_target=_orig_target,
                        resolved_ip=_resolved_ip,
                    )
                    # Save final state
                    final_state = {
                        "campaign_id": campaign_id,
                        "target": target_ip,
                        "goal": goal,
                        "aggression": agg.value,
                        "status": "completed",
                        "started_at": initial_state["started_at"],
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "current_phase": state.current_phase.value,
                        "tasks": {
                            "completed": sum(
                                1 for t in orchestrator._tasks.values() if t.status == TaskStatus.COMPLETED
                            ),
                            "failed": sum(1 for t in orchestrator._tasks.values() if t.status == TaskStatus.FAILED),
                            "pending": sum(1 for t in orchestrator._tasks.values() if t.status == TaskStatus.PENDING),
                        },
                        "compromised_hosts": _compromised_hosts_for_state(state),
                        "last_error": "",
                    }
                    _write_campaign_state(workspace, campaign_id, final_state)
                except asyncio.CancelledError:
                    cancelled_state = {
                        **initial_state,
                        "status": "cancelled",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "current_phase": state.current_phase.value if state else "unknown",
                        "last_error": "campaign task cancelled",
                    }
                    _write_campaign_state(workspace, campaign_id, cancelled_state)
                    raise
                except _EXC_GROUP_CATCH as exc:
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)
                    error_state = {
                        "campaign_id": campaign_id,
                        "target": target_ip,
                        "goal": goal,
                        "aggression": agg.value,
                        "status": "error",
                        "started_at": initial_state["started_at"],
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "current_phase": state.current_phase.value if state else "unknown",
                        "tasks": {"completed": 0, "failed": 0, "pending": 0},
                        "compromised_hosts": [],
                        "last_error": str(exc),
                    }
                    _write_campaign_state(workspace, campaign_id, error_state)

            _bg_task = asyncio.create_task(_run_campaign())
            _running_campaign_tasks.add(_bg_task)
            _campaign_orchestrators[campaign_id] = orchestrator

            def _on_done(task: asyncio.Task) -> None:
                _running_campaign_tasks.discard(task)
                _campaign_orchestrators.pop(campaign_id, None)

            _bg_task.add_done_callback(_on_done)

            lines = [
                f"CAMPAIGN_STARTED: {campaign_id}",
                f"TARGET: {target_ip}",
                f"GOAL: {goal}",
                f"AGGRESSION: {agg.value}",
                "STATUS: started",
                f"CAMPAIGN_DIR: {campaign_dir}",
                f"STATE_FILE: {campaign_dir / 'state.json'}",
                "",
                "NOTE: Campaign is running in background. Use get_campaign_status to monitor progress.",
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Campaign start failed — {exc}"

    @mcp.tool()
    @audit_tool
    def get_campaign_status(campaign_id: str) -> str:
        """Get the current status of a running or completed autonomous campaign.

        Reads the campaign's state.json file and returns the current attack phase,
        task counts, compromised hosts, and any errors.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Current AttackPhase, number of completed/failed/pending tasks, current target,
            compromised hosts, and last error if applicable.

        Example:
            get_campaign_status("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."

        try:
            _campaign_path, state_data = _read_campaign_state(workspace, campaign_id)
        except FileNotFoundError:
            return f"ERROR: Campaign '{campaign_id}' not found. Check the campaign_id or workspace path."
        except (OSError, ValueError):
            return "ERROR: Invalid campaign_id or unsafe campaign state path."

        try:
            lines = [
                f"CAMPAIGN_STATUS: {campaign_id}",
                f"TARGET: {state_data.get('target', 'unknown')}",
                f"GOAL: {state_data.get('goal', 'unknown')}",
                f"STATUS: {state_data.get('status', 'unknown')}",
                f"AGGRESSION: {state_data.get('aggression', 'unknown')}",
                f"CURRENT_PHASE: {state_data.get('current_phase', 'unknown')}",
                f"STARTED_AT: {state_data.get('started_at', 'unknown')}",
                f"COMPLETED_AT: {state_data.get('completed_at', 'N/A (running)')}",
                "",
                "TASKS:",
            ]
            tasks = state_data.get("tasks", {})
            lines.append(f"  Completed: {tasks.get('completed', 0)}")
            lines.append(f"  Failed: {tasks.get('failed', 0)}")
            lines.append(f"  Pending: {tasks.get('pending', 0)}")

            compromised = state_data.get("compromised_hosts", [])
            if compromised:
                lines.append(f"\nCOMPROMISED: {', '.join(compromised)}")
            else:
                lines.append("\nCOMPROMISED: None yet")

            last_error = state_data.get("last_error", "")
            if last_error:
                lines.append(f"\nLAST_ERROR: {last_error}")

            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Status retrieval failed — {exc}"

    @mcp.tool()
    @audit_tool
    async def run_campaign_step(campaign_id: str) -> str:
        """Execute a single pending task from an autonomous campaign synchronously.

        For step-by-step control: loads the orchestrator state, executes one pending
        task, updates state.json, and returns the task result. Useful for debugging
        or when you want to manually control campaign pacing.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Task result: module used, target, success/failure, and output summary.

        Example:
            run_campaign_step("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."

        try:
            try:
                campaign_dir, state_data = _read_campaign_state(workspace, campaign_id)
            except FileNotFoundError:
                return f"ERROR: Campaign '{campaign_id}' not found."
            except (OSError, ValueError):
                return "ERROR: Invalid campaign_id or unsafe campaign state path."
            target_ip = state_data.get("target", "")
            if not target_ip:
                return "ERROR: No target found in campaign state."

            # Target-IP lock: target_ip comes from a workspace state.json that
            # is LLM-writable, so re-check it against the allowlist before running
            # recon / attack modules -- mirrors the @require_allowlist gate that
            # start_autonomous_campaign applies to its target_ip argument. The
            # audit_tool decorator above records this call (and a BLOCKED result
            # is logged as approved=False, status=blocked).
            allowed, reason = check_targets_allowlist([target_ip], config)
            if not allowed:
                return f"CAMPAIGN_STEP_RESULT: blocked\nTARGET: {target_ip}\nBLOCKED_REASON: {reason}"

            # Build orchestrator and load state. Merge the ``autonomous``
            # config block so the opt-in Phase 2 flags flow through; explicit
            # keys below override (max_cycles=1 -- run_campaign_step is a
            # single step).
            mission_config = {
                **(config or {}).get("autonomous", {}),
                # Phase 6.2: pass the opsec block through so the orchestrator's
                # AttackModuleExecutor can build an OpsecManager and make
                # AggressionLevel.STEALTH pacing load-bearing. Absent -> {} ->
                # disabled profile -> pacing no-op (legacy behavior).
                "opsec": (config or {}).get("opsec", {}),
                # Phase 3: pass the MSF auto-local_exploit_suggester flag through.
                "msf_auto_les": (config or {})
                .get("exploit", {})
                .get("msf", {})
                .get("auto_local_exploit_suggester", False),
                # D1: pass the orchestrator.semantic_memory flag + ollama/embed
                # config through so the orchestrator can build its own
                # SemanticMemoryManager when no manager is supplied directly.
                "semantic_memory": bool((config or {}).get("orchestrator", {}).get("semantic_memory", False)),
                "ollama": (config or {}).get("ollama", {}),
                "embedding_model": (config or {}).get("memory", {}).get("embedding_model", "nomic-embed-text"),
                # §23: same agent-block merge as start_autonomous_campaign so a
                # stepped campaign honors agent.max_retries_per_task too.
                "agent": (config or {}).get("agent", {}),
                # Kill-chain state machine (design §killchain): same merge as
                # start_autonomous_campaign so stepped campaigns honor it too.
                "killchain": (config or {}).get("killchain", {}),
                # Snapshot/rollback (design §snapshots): same merge as
                # start_autonomous_campaign so stepped campaigns honor it too.
                "snapshots": (config or {}).get("snapshots", {}),
                "replay_simulator": (config or {}).get("replay_simulator", {}),
                "target": target_ip,
                "goal": state_data.get("goal", "initial_access"),
                "max_cycles": 1,
                "max_aggression": state_data.get("aggression", "normal"),
                "workspace": str(campaign_dir),
            }

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=campaign_dir,
                sandbox_recon_provider=_make_sandbox_recon_provider(
                    ctx, config, str(state_data.get("aggression", "normal"))
                ),
                require_sandbox_recon=True,
            )

            state = orchestrator.get_state(target_ip)
            # Domain targeting: restore the domain context on a step-resumed
            # campaign so state.original_target is populated (the subdomain-
            # expansion branch in _phase_reconnaissance reads it). The
            # state.json written by start_autonomous_campaign carries the
            # original target string; if it's a domain, thread it through.
            _step_orig = state_data.get("original_target", "") or ""
            _step_resolved = state_data.get("resolved_ip", "") or ""
            if _step_orig and not state.original_target:
                state.original_target = _step_orig
            if _step_resolved and not state.resolved_ip:
                state.resolved_ip = _step_resolved

            # Run just the recon phase if no recon yet, otherwise try exploitation
            if state.recon_result is None:
                recon_result = await _make_sandbox_recon_provider(
                    ctx, config, str(state_data.get("aggression", "normal"))
                )(target_ip)
                state.recon_result = recon_result
                state.current_phase = OrchAttackPhase.ENUMERATION

                # Update state
                state_data["current_phase"] = state.current_phase.value
                state_data["status"] = "running"
                _write_campaign_state(workspace, campaign_id, state_data)

                return (
                    f"CAMPAIGN_STEP_RESULT: recon_completed\n"
                    f"TARGET: {target_ip}\n"
                    f"OPEN_PORTS: {len(recon_result.open_ports)} — {recon_result.open_ports}\n"
                    f"SERVICES: {', '.join(s.service for s in recon_result.services)}\n"
                    f"NEXT_PHASE: enumeration"
                )

            # Try to run the highest-scoring applicable module
            module_ctx = ModuleContext(
                target_ip=target_ip,
                target_os=state.recon_result.os_family if state.recon_result else None,
                services=[
                    {"service": s.service, "port": f"{s.port}/{s.protocol}"}
                    for s in (state.recon_result.services if state.recon_result else [])
                ],
            )

            from tools.attack_modules import find_modules

            scored = find_modules(module_ctx)
            if not scored:
                state_data["status"] = "completed"
                state_data["current_phase"] = "done"
                _write_campaign_state(workspace, campaign_id, state_data)
                return (
                    f"CAMPAIGN_STEP_RESULT: no_applicable_modules\n"
                    f"TARGET: {target_ip}\n"
                    f"REASON: No attack modules match the current target context."
                )

            best_score, best_module = scored[0]
            result = best_module.run(module_ctx)

            # Module output is an operational result, not target-bound proof.
            # Do not append a module name to successful_exploits or report it
            # as a compromised host merely because script generation worked.
            _record_campaign_step_result(state, state_data, str(result.get("status", "")))
            state_data["current_phase"] = "exploit"
            _write_campaign_state(workspace, campaign_id, state_data)

            lines = [
                "CAMPAIGN_STEP_RESULT: executed",
                f"MODULE: {best_module.name}",
                f"TARGET: {target_ip}",
                f"APPLICABILITY_SCORE: {best_score}",
                f"STATUS: {result.get('status', 'unknown')}",
            ]
            if result.get("note"):
                lines.append(f"NOTE: {result['note']}")
            if result.get("script"):
                lines.append(f"SCRIPT_PREVIEW:\n{result['script'][:300]}")

            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Campaign step failed — {exc}"

    # ───────────────────────────────────────────────────────────────────────
    @mcp.tool()
    @audit_tool
    def stop_campaign(campaign_id: str) -> str:
        """Gracefully stop a running autonomous campaign.

        Signals the live AutonomousOrchestrator (if still running) to stop at its
        next cycle boundary. The campaign's state.json is left intact so its final
        status can still be read via get_campaign_status.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Status string indicating whether the campaign was signalled to stop,
            had already finished, or was not found.

        Example:
            stop_campaign("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."
        if not _valid_campaign_id(campaign_id):
            return "ERROR: Invalid campaign_id or unsafe campaign state path."

        orchestrator = _campaign_orchestrators.get(campaign_id)
        if orchestrator is None:
            try:
                _campaign_path, _state_data = _read_campaign_state(workspace, campaign_id)
            except FileNotFoundError:
                return f"ERROR: Campaign '{campaign_id}' not found."
            except (OSError, ValueError):
                return "ERROR: Invalid campaign_id or unsafe campaign state path."
            else:
                return f"STOPPED: Campaign '{campaign_id}' is not running (already finished)."

        orchestrator.stop()
        return f"STOPPED: Campaign '{campaign_id}' stop signal sent."

    # 6. Persistent Interactive Sessions (tools.persistent_session_manager)
    # ───────────────────────────────────────────────────────────────────────
