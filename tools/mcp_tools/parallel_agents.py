"""Parallel sub-agent MCP tools — let the main AI delegate work to specialist
swarm agents and await their results.

Phase 4 of the parallel-sub-agents plan. Exposes three MCP tools to the main
exploit agent (the LLM driving ``run_exploit_agent``):

* ``spawn_subagent(phase, target, objective, ...)`` — fire-and-forget: starts
  a specialist swarm agent (recon / vuln / exploit / post_exploit) in a
  background asyncio task and returns a ``subagent_id`` immediately. The main
  AI keeps working on the primary target while the sub-agent runs.
* ``await_subagent(subagent_id, timeout_seconds)`` — block until the
  sub-agent finishes and return its result (merged findings, output). On
  timeout returns a partial result so the main AI isn't wedged.
* ``list_subagents()`` — poll live sub-agent status (running / complete /
  failed) so the main AI can decide whether to await or move on.

Design constraint: the swarm agents (``tools/swarm/agents/*``) live in the
SAME process as the MCP server (the server imports them at boot), so a
sub-agent can call ``SwarmOrchestrator.route()`` directly — no MCP
client/server round-trip. The sub-agent uses the swarm's Path-B model
(attack modules, ReconPipeline, NVDClient, ExploitSearch — all in-process
Python calls) so it does NOT need a live MCP ``ClientSession``. This is the
crucial difference from ``ExploitAgent`` Path A (which needs the main loop's
session): the sub-agent does its recon/vuln-research work in-process and
writes results to a per-subagent JSON file the main AI reads back via
``await_subagent``.

Safety: the sub-agent inherits the same target-IP allowlist lock as the
main AI. ``spawn_subagent`` validates the target against
``is_target_in_allowlist`` (the same check every target-touching MCP tool
uses) so a sub-agent can't be spawned against an out-of-scope host. The
sub-agent's own ``ExploitPolicy`` (built inside ``ExploitAgent``) inherits
the allowlist too. Audit: each spawn/await is recorded via ``@audit_tool``,
and the sub-agent's result file is written under the workspace.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any

from tools.mcp_tools.registry import *
from tools.validation_utils import validate_target_or_ip

# ── SubagentManager (process-singleton, lifecycle tied to the MCP server) ──
#
# One instance per MCP server process. Holds the asyncio tasks for live
# sub-agents and their result files. The main AI's spawn_subagent /
# await_subagent / list_subagents calls all go through this singleton.


class _SubagentManager:
    """Tracks live sub-agent tasks and their results.

    A process-singleton (one instance per MCP server process). The swarm
    agents run in-process via ``SwarmOrchestrator.route()`` (Path B — no live
    MCP ClientSession needed; the agents use ReconPipeline / NVDClient /
    attack modules directly). Results are written to per-subagent JSON files
    under the workspace so ``await_subagent`` can read them back even if the
    task already completed.
    """

    def __init__(self, workspace: Path, config: dict[str, Any] | None) -> None:
        self._workspace = workspace
        self._config = config or {}
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._orchestrator: Any = None  # lazy-built SwarmOrchestrator

    def _get_orchestrator(self) -> Any:
        """Lazily build a SwarmOrchestrator for sub-agent dispatch.

        Built once per process. Uses a minimal context: the config (so agents
        get NVD/ExploitSearch settings), a workspace root, and a fresh
        Blackboard (the sub-agent's findings land here, then get serialized to
        the result file). Critic/reflection are off by default for sub-agents
        (the main AI is the strategist; the sub-agent is a worker).
        """
        if self._orchestrator is not None:
            return self._orchestrator
        from tools.swarm.orchestrator import SwarmOrchestrator

        context = {
            "config": self._config,
            "workspace_root": self._workspace,
            "reports_dir": self._workspace,
        }
        self._orchestrator = SwarmOrchestrator(
            context,
            critic_enabled=False,
            reflection_enabled=False,
            state_path=self._workspace / "subagent_swarm_state.json",
        )
        return self._orchestrator

    async def spawn(
        self,
        phase: str,
        target: str,
        objective: str,
        services: list[str] | None = None,
        known_cves: list[str] | None = None,
    ) -> dict[str, Any]:
        """Spawn a sub-agent for ``phase`` against ``target``. Returns
        ``{subagent_id, status: "running"}`` immediately."""
        subagent_id = f"subagent-{phase}-{uuid.uuid4().hex[:8]}"
        result_path = self._workspace / "subagents" / f"{subagent_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)

        task_dict = {
            "task_id": subagent_id,
            "phase": phase,
            "target": target,
            "objective": objective,
            "services": services or [],
            "known_cves": known_cves or [],
            "_result_path": str(result_path),
        }

        async def _run() -> None:
            """Run the sub-agent in-process via SwarmOrchestrator.route().

            Catches all exceptions so a failed sub-agent records a result the
            main AI can read via await_subagent, rather than silently
            disappearing.
            """
            start = time.monotonic()
            result_dict: dict[str, Any] = {
                "subagent_id": subagent_id,
                "phase": phase,
                "target": target,
                "objective": objective,
                "status": "running",
                "started_at": time.time(),
            }
            try:
                orch = self._get_orchestrator()
                # route() is sync (uses run_in_executor internally for
                # route_parallel, but a single route() is sync). Run it in a
                # worker thread so we don't block the MCP server's event loop.
                agent_result = await asyncio.to_thread(orch.route, task_dict)
                result_dict["status"] = agent_result.status.value
                result_dict["output"] = agent_result.output
                result_dict["error"] = agent_result.error
                result_dict["findings"] = agent_result.findings
                result_dict["new_tasks"] = agent_result.new_tasks
                result_dict["execution_time"] = time.monotonic() - start
            except Exception as exc:  # noqa: BLE001 — never silently drop a sub-agent  # ponytail: bare except intentional
                result_dict["status"] = "failed"
                result_dict["error"] = f"subagent crashed: {exc}"
                result_dict["execution_time"] = time.monotonic() - start
            finally:
                result_dict["completed_at"] = time.time()
                # Write the result file so await_subagent can read it back
                # even after the task is gone. Atomic write (os.replace).
                try:
                    tmp = result_path.with_suffix(".tmp")
                    tmp.write_text(json.dumps(result_dict, indent=2, default=str), encoding="utf-8")
                    import os as _os

                    _os.replace(tmp, result_path)
                except Exception:  # noqa: BLE001 — best-effort persist  # ponytail: bare except intentional
                    pass
                async with self._lock:
                    self._results[subagent_id] = result_dict
                    self._tasks.pop(subagent_id, None)

        # Store the started-time result so list_subagents shows it immediately.
        async with self._lock:
            self._results[subagent_id] = {
                "subagent_id": subagent_id,
                "phase": phase,
                "target": target,
                "objective": objective,
                "status": "running",
                "started_at": time.time(),
            }
        self._tasks[subagent_id] = asyncio.create_task(_run())
        return {"subagent_id": subagent_id, "status": "running"}

    async def await_result(self, subagent_id: str, timeout_seconds: int = 600) -> dict[str, Any]:
        """Block until the sub-agent finishes, or timeout. Returns its result."""
        async with self._lock:
            task = self._tasks.get(subagent_id)
            cached = self._results.get(subagent_id)

        # If the task already completed, return the cached result immediately.
        if task is None:
            if cached is not None:
                return cached
            return {
                "subagent_id": subagent_id,
                "status": "unknown",
                "error": f"no sub-agent with id {subagent_id!r}",
            }

        # Wait for the task, with a ceiling so a stuck sub-agent can't wedge
        # the main AI forever. ``asyncio.wait_for`` raises TimeoutError; we
        # catch it and return a partial/timeout result instead of raising
        # (the main AI's tool call shouldn't crash on a slow sub-agent).
        try:
            await asyncio.wait_for(task, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            return {
                "subagent_id": subagent_id,
                "status": "timeout",
                "error": f"sub-agent did not finish within {timeout_seconds}s",
                "partial": cached or {},
            }
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return {
                "subagent_id": subagent_id,
                "status": "failed",
                "error": f"sub-agent task raised: {exc}",
            }

        async with self._lock:
            return self._results.get(
                subagent_id,
                {
                    "subagent_id": subagent_id,
                    "status": "unknown",
                    "error": "sub-agent finished but no result was recorded",
                },
            )

    def list_live(self) -> list[dict[str, Any]]:
        """Return a snapshot of all sub-agents and their current status."""
        # Read the cached results (the spawn pre-populates "running"; the
        # task updates _results on completion). Don't block on the lock here —
        # list_subagents is a polling call and shouldn't serialize on a busy
        # sub-agent.
        return list(self._results.values())


# Process-singleton. Lazily initialized on first spawn_subagent call so the
# MCP server doesn't pay the SwarmOrchestrator construction cost until the
# main AI actually delegates.
_MANAGER: _SubagentManager | None = None


def _get_manager(workspace: Path, config: dict[str, Any] | None) -> _SubagentManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = _SubagentManager(workspace, config)
    return _MANAGER


# ── MCP tool registration ─────────────────────────────────────────────────


def register_parallel_agent_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register spawn_subagent / await_subagent / list_subagents MCP tools.

    Conditionally registered: only when ``swarm.parallel_enabled`` is true
    (the recon-first rollout gate; off by default so a fresh config never
    silently exposes the delegation surface). The gate is read at
    registration time (MCP server boot), so toggling the config requires a
    server restart — matching how the other conditionally-registered tools
    (runtime_skills, peer_models) work.
    """
    workspace = ctx.workspace
    config = ctx.config or {}
    audit_tool = ctx.audit_tool

    swarm_cfg = config.get("swarm", {}) or {}
    parallel_enabled = bool(swarm_cfg.get("parallel_enabled", False))
    if not parallel_enabled:
        return

    @mcp.tool()
    @audit_tool
    async def spawn_subagent(
        phase: str,
        target: str,
        objective: str,
        services: list[str] | None = None,
        known_cves: list[str] | None = None,
    ) -> str:
        """Spawn a specialist sub-agent to work in parallel while you continue
        the main assessment. Returns immediately with a subagent_id; call
        await_subagent to collect the result.

        Use this to parallelize: spawn a recon sub-agent on a second host
        while you exploit the first; spawn a vuln-research sub-agent on a
        service while you attack another. The sub-agent shares your target
        allowlist and audit trail — it cannot attack hosts outside your scope.

        Args:
            phase: Agent specialty — 'recon', 'analysis' (vuln research),
                   'exploit', or 'post_exploit'.
            target: Target IP (must be in your allowlist).
            objective: One-line description of what the sub-agent should do.
            services: Optional list of services (for vuln/exploit phases).
            known_cves: Optional list of CVE IDs (for exploit phase).

        Returns:
            subagent_id and status='running'. Poll with list_subagents or
            block with await_subagent.

        Example:
            spawn_subagent("recon", "10.0.0.6", "Full port scan + service ID")
        """
        # Validate phase.
        valid_phases = ("recon", "analysis", "exploit", "post_exploit")
        if phase not in valid_phases:
            return f"BLOCKED: phase must be one of {valid_phases}, got {phase!r}."

        # Validate target.
        if not validate_target_or_ip(target):
            return f"BLOCKED: invalid target {target!r} (must be IP or FQDN)."

        # Target-IP allowlist lock: the sub-agent inherits the same scope as
        # the main AI. This is THE safety property — parallelizing agents
        # does NOT parallelize the attack surface. The sub-agent's own
        # ExploitPolicy re-checks this, but we refuse at spawn time so an
        # out-of-scope delegation never starts a task. ``check_targets_allowlist``
        # is the same gate every target-touching MCP tool uses (payloads,
        # metasploit, attack_modules).
        allowed, reason = check_targets_allowlist([target], config)
        if not allowed:
            return f"BLOCKED: target {target!r} not in allowlist: {reason}"

        manager = _get_manager(workspace, config)
        result = await manager.spawn(
            phase=phase,
            target=target,
            objective=objective,
            services=services,
            known_cves=known_cves,
        )
        return json.dumps(result, default=str)

    @mcp.tool()
    @audit_tool
    async def await_subagent(subagent_id: str, timeout_seconds: int = 600) -> str:
        """Block until a spawned sub-agent finishes and return its result.

        Use after spawn_subagent to collect the sub-agent's findings. If the
        sub-agent is still running when timeout_seconds elapses, returns a
        'timeout' status with whatever partial result is available — your
        main loop can poll again or move on.

        Args:
            subagent_id: The id returned by spawn_subagent.
            timeout_seconds: Max wait (default 600 = 10 min). Ceiling prevents
                             a stuck sub-agent from wedging your loop.

        Returns:
            JSON with the sub-agent's status ('complete'/'failed'/'timeout'),
            output, findings, and any error.
        """
        if not subagent_id or not subagent_id.strip():
            return "BLOCKED: subagent_id is required."
        timeout = max(1, min(int(timeout_seconds), 3600))  # cap at 1 hour
        manager = _get_manager(workspace, config)
        result = await manager.await_result(subagent_id, timeout_seconds=timeout)
        return json.dumps(result, default=str)

    @mcp.tool()
    @audit_tool
    def list_subagents() -> str:
        """List all spawned sub-agents and their current status.

        Use to poll multiple spawned sub-agents without blocking on any one.
        Returns one entry per spawned sub-agent with its phase, target, and
        status (running/complete/failed).

        Returns:
            JSON array of {subagent_id, phase, target, status, started_at}.
        """
        manager = _get_manager(workspace, config)
        live = manager.list_live()
        return json.dumps(live, default=str)
