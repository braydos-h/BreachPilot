"""Autonomous campaign MCP tools (split from god file)."""

from __future__ import annotations

import hashlib

from tools.mcp_tools.registry import *

# Strong references to background campaign tasks. CPython's event loop holds
# only a weak ref to a task, so an unreferenced asyncio.create_task() can be
# garbage-collected mid-run and the campaign's final/error state.json is never
# written (leaving it permanently "running"). The done-callback drops the ref
# once the task finishes so completed campaigns don't leak.
_running_campaign_tasks: set = set()

# campaign_id -> live AutonomousOrchestrator, so stop_campaign can signal a
# graceful stop. Popped when the background task finishes (see the done
# callback in start_autonomous_campaign).
_campaign_orchestrators: dict[str, Any] = {}


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

            campaign_id = f"campaign-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}-{hashlib.sha256(target_ip.encode()).hexdigest()[:8]}"
            campaign_dir = workspace / "campaigns" / campaign_id
            campaign_dir.mkdir(parents=True, exist_ok=True)

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
            (campaign_dir / "state.json").write_text(json.dumps(initial_state, indent=2, default=str), encoding="utf-8")

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
                        "compromised_hosts": state.successful_exploits,
                        "last_error": "",
                    }
                    (campaign_dir / "state.json").write_text(
                        json.dumps(final_state, indent=2, default=str), encoding="utf-8"
                    )
                except Exception as exc:
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
                    (campaign_dir / "state.json").write_text(
                        json.dumps(error_state, indent=2, default=str), encoding="utf-8"
                    )

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
        except Exception as exc:
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
            state_path = workspace / "campaigns" / campaign_id / "state.json"
            if not state_path.exists():
                return f"ERROR: Campaign '{campaign_id}' not found. Check the campaign_id or workspace path."

            state_data = json.loads(state_path.read_text(encoding="utf-8"))

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
        except Exception as exc:
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
            campaign_dir = workspace / "campaigns" / campaign_id
            state_path = campaign_dir / "state.json"
            if not state_path.exists():
                return f"ERROR: Campaign '{campaign_id}' not found."

            state_data = json.loads(state_path.read_text(encoding="utf-8"))
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
                "target": target_ip,
                "goal": state_data.get("goal", "initial_access"),
                "max_cycles": 1,
                "max_aggression": state_data.get("aggression", "normal"),
                "workspace": str(campaign_dir),
            }

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=campaign_dir,
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
                recon_config = ReconConfig()
                pipeline = ReconPipeline(recon_config)
                recon_result = await pipeline.recon_host(target_ip)
                state.recon_result = recon_result
                state.current_phase = OrchAttackPhase.ENUMERATION

                # Update state
                state_data["current_phase"] = state.current_phase.value
                state_data["status"] = "running"
                (campaign_dir / "state.json").write_text(
                    json.dumps(state_data, indent=2, default=str), encoding="utf-8"
                )

                return (
                    f"CAMPAIGN_STEP_RESULT: recon_completed\n"
                    f"TARGET: {target_ip}\n"
                    f"OPEN_PORTS: {len(recon_result.open_ports)} — {recon_result.open_ports}\n"
                    f"SERVICES: {', '.join(s.service for s in recon_result.services)}\n"
                    f"NEXT_PHASE: enumeration"
                )

            # Try to run the highest-scoring applicable module
            ctx = ModuleContext(
                target_ip=target_ip,
                target_os=state.recon_result.os_family if state.recon_result else None,
                services=[
                    {"service": s.service, "port": f"{s.port}/{s.protocol}"}
                    for s in (state.recon_result.services if state.recon_result else [])
                ],
            )

            from tools.attack_modules import find_modules

            scored = find_modules(ctx)
            if not scored:
                state_data["status"] = "completed"
                state_data["current_phase"] = "done"
                (campaign_dir / "state.json").write_text(
                    json.dumps(state_data, indent=2, default=str), encoding="utf-8"
                )
                return (
                    f"CAMPAIGN_STEP_RESULT: no_applicable_modules\n"
                    f"TARGET: {target_ip}\n"
                    f"REASON: No attack modules match the current target context."
                )

            best_score, best_module = scored[0]
            result = best_module.run(ctx)

            # Update state
            tasks = state_data.get("tasks", {})
            if result.get("status") in ("success", "exploited", "script_generated"):
                tasks["completed"] = tasks.get("completed", 0) + 1
                state.successful_exploits.append(best_module.name)
                state_data["compromised_hosts"] = state.successful_exploits
            else:
                tasks["failed"] = tasks.get("failed", 0) + 1

            state_data["tasks"] = tasks
            state_data["current_phase"] = "exploit"
            (campaign_dir / "state.json").write_text(json.dumps(state_data, indent=2, default=str), encoding="utf-8")

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
        except Exception as exc:
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

        orchestrator = _campaign_orchestrators.get(campaign_id)
        if orchestrator is None:
            state_path = workspace / "campaigns" / campaign_id / "state.json"
            if state_path.exists():
                return f"STOPPED: Campaign '{campaign_id}' is not running (already finished)."
            return f"ERROR: Campaign '{campaign_id}' not found."

        orchestrator.stop()
        return f"STOPPED: Campaign '{campaign_id}' stop signal sent."

    # 6. Persistent Interactive Sessions (tools.persistent_session_manager)
    # ───────────────────────────────────────────────────────────────────────
