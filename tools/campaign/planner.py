"""Campaign planner — phase machine + vuln chaining."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from tools.attack_modules import find_modules, find_producers
from tools.attack_ui import get_ui
from tools.campaign.state import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    RetryEngine,
    TaskStatus,
    _report_autonomous_progress,
)
from tools.exceptions import _EXC_GROUP_CATCH
from tools.logging_setup import get_logger
from tools.validation_utils import is_local_target

logger = get_logger()
ui = get_ui()


class PlannerMixin:
    _workspace: Any
    _mission: dict[str, Any]
    _executor: Any
    _states: dict[str, AttackState]
    _tasks: dict[str, AttackTask]
    _task_counter: int
    _running: bool
    _max_cycles: int
    _max_aggression: AggressionLevel
    _max_pivot_depth: int
    _persistence_enabled: bool
    _adaptive_replan: bool
    _hard_target_max_rounds: int
    _recon: Any
    _tool_executor: Any
    _experience_store: Any
    _prereq_tasks_added: int
    _prereq_recovery_cap: int
    _max_module_failures: int = 3

    def _new_task_id(self) -> str:  # type: ignore[override]
        self._task_counter += 1
        return f"ATK-{self._task_counter:05d}"

    def get_state(self, target: str) -> AttackState:  # type: ignore[override]
        if target not in self._states:
            state = AttackState(target=target)
            orig = getattr(self, "_original_target", "")
            res = getattr(self, "_resolved_ip", "")
            if orig and not state.original_target:
                state.original_target = orig
            if res and not state.resolved_ip:
                state.resolved_ip = res
            self._states[target] = state
        return self._states[target]

    def _module_context(self, state: AttackState, task: AttackTask | None = None):  # type: ignore[override]
        from tools.attack_modules import ModuleContext

        services_full: list[dict[str, Any]] = []
        cves: list[str] = []
        for s in state.recon_result.services if state.recon_result else []:
            services_full.append(
                {
                    "service": s.service,
                    "port": f"{s.port}/{s.protocol}",
                    "version": s.version,
                    "cpe": list(s.cpe),
                    "banner": s.banner,
                }
            )
            openssh = s.scripts.get("openssh_cves", [])
            if isinstance(openssh, str):
                cves.extend(re.findall(r"CVE-\d{4}-\d{4,}", openssh, re.IGNORECASE))
            else:
                for cve in openssh:
                    cves.append(str(cve))
            for key, val in s.scripts.items():
                if key == "openssh_cves":
                    continue
                if isinstance(val, str):
                    cves.extend(re.findall(r"CVE-\d{4}-\d{4,}", val, re.IGNORECASE))
        return ModuleContext(
            target_ip=state.target,
            target_os=state.recon_result.os_family if state.recon_result else "",
            services=services_full,
            cves=sorted(set(cves)),
            credentials=list(state.credentials_found),
            config=self._mission,
            parameters=dict(task.parameters) if task is not None else {},
            access_achieved=state.access_achieved,
            privilege_level=state.privilege_level,
            sessions=([{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []),
            phase=state.current_phase.value,
            evidence_refs=list(state.loot)[-10:],
        )

    async def _phase_local_takeover(self, state: AttackState) -> None:
        logger.info(f"[LOCAL] Target {state.target} is this host -- local-takeover phase")
        ui.phase_change("local_takeover")
        state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event(
            "local_takeover", "Local-target playbook: filesystem enumeration + privilege escalation"
        )
        local_cmds = [
            "cat /etc/passwd",
            "sudo -n cat /etc/shadow 2>/dev/null",
            "ls -la /home/*/.ssh /root/.ssh 2>/dev/null",
            "find / -perm -4000 -type f 2>/dev/null",
            "find / -perm -2000 -type f 2>/dev/null",
            "find / -writable -type d 2>/dev/null | head",
            "cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null",
            "ls -la /opt /srv /var/www /etc/mysql",
            "grep -rIl 'password' /etc/ 2>/dev/null | head",
            "env; cat ~/.bash_history ~/.zsh_history 2>/dev/null",
        ]
        if self._tool_executor:
            for cmd in local_cmds:
                try:
                    out = await asyncio.to_thread(self._tool_executor, cmd, {"target": state.target})
                    state.add_timeline_event("local_read", cmd, {"output_len": len(str(out or ""))})
                except _EXC_GROUP_CATCH as exc:
                    state.add_timeline_event("local_read_err", f"{cmd}: {exc}")
        else:
            state.add_timeline_event(
                "local_read_skipped", "No tool_executor wired -- privesc modules still run local enumeration"
            )
        await self._phase_privilege_escalation(state)

    async def _phase_reconnaissance(self, state: AttackState) -> None:
        logger.info(f"[RECON] Starting reconnaissance against {state.target}")
        ui.phase_change("reconnaissance")
        state.current_phase = AttackPhase.RECONNAISSANCE
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Reconnaissance phase started")
        if state.recon_result and state.recon_result.open_ports:
            logger.info(
                f"[RECON] Resuming with prior recon ({len(state.recon_result.open_ports)} ports) — skipping re-scan"
            )
            state.add_timeline_event(
                "recon_reused",
                f"Reused prior recon with {len(state.recon_result.open_ports)} open ports",
                {"ports": state.recon_result.open_ports, "resumed": True},
            )
            return
        recon_result = await self._recon.recon_host(state.target)
        state.recon_result = recon_result
        if recon_result.open_ports:
            state.add_timeline_event(
                "recon_complete",
                f"Found {len(recon_result.open_ports)} open ports",
                {"ports": recon_result.open_ports, "services": [s.service for s in recon_result.services]},
            )
            logger.info(f"[RECON] Found {len(recon_result.open_ports)} ports on {state.target}")
        else:
            state.add_timeline_event("recon_empty", "No open ports found")
        if state.original_target and state.original_target != state.target:
            try:
                from tools.mcp_shared import add_discovered_target
                from tools.validation_utils import is_fqdn, is_subdomain_of, resolve_target_to_ip

                if is_fqdn(state.original_target):
                    logger.info(
                        f"[RECON] Domain target {state.original_target} -- expanding attack surface via subdomain enumeration"
                    )
                    import json as _json
                    import urllib.request as _urlreq

                    dom = state.original_target.strip().lower()
                    try:
                        req = _urlreq.Request(
                            f"https://crt.sh/?q=%25.{dom}&output=json",
                            headers={"User-Agent": "NetAttackAi-Orchestrator/1.0"},
                        )
                        with _urlreq.urlopen(req, timeout=20) as resp:  # noqa: S310
                            body = resp.read().decode(errors="replace")
                        subs: set[str] = set()
                        if body:
                            for row in _json.loads(body):
                                for nv in str(row.get("name_value", "")).splitlines():
                                    for s in nv.split(","):
                                        s = s.strip().lstrip("*.").strip().lower()
                                        if s and is_subdomain_of(s, dom) and s != dom:
                                            subs.add(s)
                        for sub in sorted(subs)[:200]:
                            ip = resolve_target_to_ip(sub)
                            if ip:
                                state.discovered_subdomains.append({"subdomain": sub, "ip": ip})
                                add_discovered_target(sub, ip)
                    except _EXC_GROUP_CATCH as exc:
                        logger.warning(f"[RECON] Subdomain expansion failed for {dom}: {exc}")
                    if state.discovered_subdomains:
                        state.add_timeline_event(
                            "subdomain_expansion",
                            f"Discovered {len(state.discovered_subdomains)} subdomains",
                            {"subdomains": state.discovered_subdomains[:20]},
                        )
                        logger.info(
                            f"[RECON] Discovered {len(state.discovered_subdomains)} subdomains of {state.original_target}"
                        )
            except _EXC_GROUP_CATCH as exc:
                logger.warning(f"[RECON] Domain expansion hook failed: {exc}")

    async def _phase_exploitation(self, state: AttackState, *, skip_failed: bool = False) -> None:
        logger.info(f"[EXPLOIT] Starting exploitation against {state.target}")
        ui.phase_change("exploitation")
        state.current_phase = AttackPhase.EXPLOITATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Exploitation phase started")
        if not state.recon_result:
            logger.warning("No recon result available for exploitation")
            return
        ctx = self._module_context(state)
        scored_modules = find_modules(ctx, experience_store=self._experience_store)
        if skip_failed:
            failed = set(state.failed_attempts.keys())
            scored_modules = [(s, m) for (s, m) in scored_modules if m.name not in failed]
            logger.info(
                f"[EXPLOIT] Adaptive replan: {len(scored_modules)} modules after dropping {len(failed)} previously-failed"
            )
        logger.info(f"[EXPLOIT] {len(scored_modules)} applicable modules found")
        tasks: list[AttackTask] = []
        ranked_names: set[tuple[str, str]] = set()
        for score, module in scored_modules[:15]:
            _port = ""
            for s in state.recon_result.services:
                if s.service.lower() in {t.lower() for t in module.target_services}:
                    _port = f"{s.port}/{s.protocol}"
                    break
            ranked_names.add((module.name, _port))
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.EXPLOITATION,
                module_name=module.name,
                target=state.target,
                parameters={"score": score, **module.to_json()},
                aggression=state.aggression,
                priority=score,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task
        service_tasks = self._create_service_specific_tasks(state)
        for st in service_tasks:
            _key = (st.module_name, str(st.parameters.get("port", "")))
            if _key in ranked_names:
                logger.info(f"[EXPLOIT] Dropping duplicate service task {st.module_name} on {_key[1]}")
                continue
            tasks.append(st)
        await self._execute_task_batch(tasks, state)
        if not state.access_achieved and state.aggression != self._max_aggression:
            state.escalate_aggression()
            logger.info(f"[EXPLOIT] Escalating aggression to {state.aggression.value}, retrying failed modules")
            await self._retry_failed_modules(state)

    async def _phase_privilege_escalation(self, state: AttackState) -> None:
        logger.info(f"[PRIVESC] Starting privilege escalation against {state.target}")
        ui.phase_change("privilege_escalation")
        state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Privilege escalation phase started")
        privesc_modules: list[str] = []
        if state.recon_result and "linux" in state.recon_result.os_family.lower():
            privesc_modules = ["LinuxPrivescCheck", "SUIDEnumeration", "KernelExploitCheck"]
        elif state.recon_result and "windows" in state.recon_result.os_family.lower():
            privesc_modules = ["WindowsPrivescCheck", "TokenImpersonation", "ServiceMisconfiguration"]
        else:
            privesc_modules = ["LinuxPrivescCheck", "WindowsPrivescCheck", "ContainerBreakout"]
        if state.recon_result:
            open_ports = {s.port for s in state.recon_result.services}
            cloud_ports = {2375, 2376, 10250, 6443, 443, 80}
            os_hint = (state.recon_result.os_family or "").lower()
            if open_ports & cloud_ports or "cloud" in os_hint or "container" in os_hint:
                privesc_modules += ["CloudPrivesc", "K8sPrivesc", "IMDSExploit", "DockerSockEscape", "S3BucketTakeover"]
        tasks: list[AttackTask] = []
        for mod_name in privesc_modules:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                module_name=mod_name,
                target=state.target,
                aggression=state.aggression,
                priority=80,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task
        await self._execute_task_batch(tasks, state)
        auto_les = getattr(self, "_auto_local_exploit_suggester", False)
        if auto_les and state.access_achieved:
            les_task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                module_name="LocalExploitSuggester",
                target=state.target,
                aggression=state.aggression,
                priority=60,
            )
            self._tasks[les_task.task_id] = les_task
            await self._executor.execute(les_task, state)
            state.add_timeline_event(
                "local_exploit_suggester", "Advisory local_exploit_suggester follow-up dispatched (info-only)"
            )

    async def _phase_lateral_movement(self, state: AttackState, _depth: int = 0) -> None:
        logger.info(f"[LATERAL] Starting lateral movement from {state.target} (pivot depth {_depth})")
        ui.phase_change("lateral_movement")
        state.current_phase = AttackPhase.LATERAL_MOVEMENT
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Lateral movement phase started")
        if is_local_target(state.target):
            state.add_timeline_event(
                "lateral_skip_local", "Skipping lateral movement -- target is this host (no pivot from self)"
            )
            logger.info(f"[LATERAL] Skipping lateral movement for local target {state.target}")
            return
        for pivot in state.pivot_targets[:5]:
            if pivot in self._states:
                state.add_timeline_event("lateral_skip", f"Skipping already-attacked pivot {pivot}")
                continue
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.LATERAL_MOVEMENT,
                module_name="LateralMovement",
                target=pivot,
                parameters={"source": state.target},
                aggression=state.aggression,
                priority=70,
            )
            self._tasks[task.task_id] = task
            result = await self._executor.execute(task, state)
            if result.get("success"):
                state.add_timeline_event("lateral_success", f"Moved to {pivot}")
                if _depth + 1 < self._max_pivot_depth:
                    await self._attack_target(pivot, _depth=_depth + 1)
                else:
                    state.add_timeline_event(
                        "pivot_depth_cap",
                        f"Pivot-depth cap ({self._max_pivot_depth}) reached; not recursing into {pivot}",
                    )
                    logger.info(f"[LATERAL] Pivot-depth cap reached at {pivot} (depth {_depth + 1})")
            else:
                state.add_timeline_event("lateral_failed", f"Failed to move to {pivot}: {result.get('error')}")

    async def _phase_validation(self, state: AttackState) -> None:
        logger.info(f"[VALIDATE] Starting validation for {state.target}")
        ui.phase_change("validation")
        state.current_phase = AttackPhase.VALIDATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Validation phase started")
        for exploit in state.successful_exploits:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.VALIDATION,
                module_name="ValidateFinding",
                target=state.target,
                parameters={"exploit": exploit},
                priority=90,
            )
            self._tasks[task.task_id] = task
            await self._executor.execute(task, state)

    async def _run_adaptive_rounds(self, state: AttackState, _depth: int) -> None:
        max_rounds = max(1, int(self._max_cycles))
        rounds = 0
        while rounds < max_rounds and self._running:
            rounds += 1
            state.add_timeline_event("adaptive_round", f"Adaptive round {rounds}/{max_rounds}")
            logger.info(f"[ADAPTIVE] {state.target} round {rounds}/{max_rounds}")
            _before = len(self._tasks)
            await self._phase_exploitation(state, skip_failed=True)
            _after = len(self._tasks)
            if _after == _before and not state.access_achieved:
                logger.info(
                    f"[ADAPTIVE] {state.target} round {rounds}: no novel candidate modules remain and no access achieved; stopping."
                )
                state.add_timeline_event(
                    "adaptive_stop", "No novel candidate modules remain; stopping adaptive rounds."
                )
                break
            if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
                await self._phase_privilege_escalation(state)
            if state.pivot_targets:
                await self._phase_lateral_movement(state, _depth)
            self._schedule_vuln_chain(state)
            if not state.access_achieved:
                state.hard_target_rounds += 1
                if self._hard_target_max_rounds and state.hard_target_rounds >= self._hard_target_max_rounds:
                    logger.info(
                        f"[ADAPTIVE] {state.target} gave up after {state.hard_target_rounds} rounds with no access (hard_target_max_rounds={self._hard_target_max_rounds})"
                    )
                    state.add_timeline_event(
                        "hard_target_give_up",
                        f"Target {state.target} produced no access in {state.hard_target_rounds} adaptive rounds; giving up to preserve campaign budget for remaining targets.",
                        {"rounds": state.hard_target_rounds},
                    )
                    break
            if not state.should_continue():
                break

    def _schedule_vuln_chain(self, state: AttackState) -> None:
        if not state.successful_exploits:
            return
        tail = f"exploit:{state.successful_exploits[-1]}"
        chains: list[list[str]] = []
        for cred in state.credentials_found[-3:]:
            chains.append([tail, f"creds:{cred}"])
        for pivot in state.pivot_targets[:5]:
            chains.append([tail, f"pivot:{pivot}"])
        if chains:
            state.attack_paths.extend(chains)
            state.add_timeline_event(
                "vuln_chain_scheduled", f"Scheduled {len(chains)} vuln-chain step(s) from {tail}", {"chains": chains}
            )

    async def _execute_task_batch(self, tasks: list[AttackTask], state: AttackState) -> None:
        semaphore = asyncio.Semaphore(3)
        prereq_scheduled: set[str] = set()

        async def run_task(task: AttackTask) -> None:
            while True:
                async with semaphore:
                    result = await self._executor.execute(task, state)
                if not result.get("success") and not result.get("blocked"):
                    if task.created_from != "recovery:prerequisite" and task.task_id not in prereq_scheduled:
                        prereq_task = self._maybe_schedule_prereq(task, state, result.get("error", ""))
                        if prereq_task is not None:
                            prereq_scheduled.add(task.task_id)
                            await run_task(prereq_task)
                    if RetryEngine.should_retry(
                        task.module_name, result.get("error", ""), task.retry_count, task.max_retries
                    ):
                        task.retry_count += 1
                        task.parameters.update(RetryEngine.get_retry_parameters(task.module_name, task.retry_count))
                        task.status = TaskStatus.RETRYING
                        logger.info(
                            f"Retrying {task.module_name} with modified parameters (attempt {task.retry_count})"
                        )
                        await asyncio.sleep(2**task.retry_count)
                        continue
                return

        await asyncio.gather(*[run_task(t) for t in tasks], return_exceptions=True)

    _PREREQ_KIND_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
        (re.compile(r"credential|creds|password|hash", re.IGNORECASE), ("credentials", "hash_artifact")),
        (re.compile(r"foothold|session|\bshell\b|webshell", re.IGNORECASE), ("foothold", "shell", "webshell")),
        (re.compile(r"admin|root|privilege|high_priv|admin_priv", re.IGNORECASE), ("high_priv", "admin_priv")),
    )

    @classmethod
    def _prereq_artifact_kinds(cls, error: str) -> list[str]:
        kinds: list[str] = []
        for pat, ks in cls._PREREQ_KIND_PATTERNS:
            if pat.search(error or ""):
                kinds.extend(ks)
        return kinds

    def _maybe_schedule_prereq(self, task: AttackTask, state: AttackState, error: str) -> AttackTask | None:
        try:
            from tools.failure_taxonomy import FailureClass, classify_failure

            fc = classify_failure(error)
        except _EXC_GROUP_CATCH:
            return None
        from tools.failure_taxonomy import FailureClass

        if fc != FailureClass.PREREQUISITE_MISSING:
            return None
        kinds = self._prereq_artifact_kinds(error)
        if not kinds:
            return None
        if self._prereq_tasks_added >= self._prereq_recovery_cap:
            return None
        for kind in kinds:
            for mod in find_producers(kind):
                if mod.name == task.module_name:
                    continue
                prereq_task = AttackTask(
                    task_id=self._new_task_id(),
                    phase=task.phase,
                    module_name=mod.name,
                    target=state.target,
                    aggression=task.aggression,
                    priority=min(100, task.priority + 10),
                    created_from="recovery:prerequisite",
                )
                self._tasks[prereq_task.task_id] = prereq_task
                self._prereq_tasks_added += 1
                logger.info(
                    f"[RECOVERY] Scheduled prerequisite producer {mod.name} (produces {kind}) for failed {task.module_name} ({error!r})"
                )
                return prereq_task
        return None

    async def _retry_failed_modules(self, state: AttackState) -> None:
        all_failed = set(state.failed_attempts.keys()) - set(state.successful_exploits)
        failed_modules = {m for m in all_failed if len(state.failed_attempts.get(m, [])) < self._max_module_failures}
        dropped = all_failed - failed_modules
        if dropped:
            logger.info(
                f"Not retrying {len(dropped)} module(s) at failure cap ({self._max_module_failures}): {sorted(dropped)}"
            )
        tasks: list[AttackTask] = []
        for mod_name in failed_modules:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.EXPLOITATION,
                module_name=mod_name,
                target=state.target,
                aggression=state.aggression,
                priority=60,
                max_retries=2,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task
        if tasks:
            logger.info(f"Retrying {len(tasks)} failed modules with {state.aggression.value} aggression")
            await self._execute_task_batch(tasks, state)

    def _create_service_specific_tasks(self, state: AttackState) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        if not state.recon_result:
            return tasks
        for svc in state.recon_result.services:
            service = svc.service.lower()
            port = svc.port
            if service == "ssh":
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SSHBruteForce",
                        target=state.target,
                        parameters={"port": port, "version": svc.version},
                        priority=75,
                    )
                )
                if "CVE-2024-6387" in str(svc.scripts.get("openssh_cves", "")):
                    tasks.append(
                        AttackTask(
                            task_id=self._new_task_id(),
                            phase=AttackPhase.EXPLOITATION,
                            module_name="RegreSSHion",
                            target=state.target,
                            parameters={"port": port},
                            priority=95,
                        )
                    )
            elif service in ("microsoft-ds", "smb", "netbios-ssn"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SMBRelay",
                        target=state.target,
                        parameters={"port": port},
                        priority=70,
                    )
                )
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SMBNullSession",
                        target=state.target,
                        parameters={"port": port},
                        priority=65,
                    )
                )
            elif service in ("http", "https", "http-proxy"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="WebShellUpload",
                        target=state.target,
                        parameters={"port": port, "scheme": service},
                        priority=70,
                    )
                )
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SQLInjection",
                        target=state.target,
                        parameters={"port": port, "scheme": service},
                        priority=65,
                    )
                )
            elif service == "ftp":
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="FTPAnonymous",
                        target=state.target,
                        parameters={"port": port},
                        priority=60,
                    )
                )
            elif service == "redis":
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="RedisExploit",
                        target=state.target,
                        parameters={"port": port},
                        priority=75,
                    )
                )
            elif port in (2375, 2376, 6443, 10250):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="ContainerBreakout",
                        target=state.target,
                        parameters={"port": port},
                        priority=80,
                    )
                )
            elif service in ("ms-wbt-server", "rdp"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="RDPExploit",
                        target=state.target,
                        parameters={"port": port},
                        priority=70,
                    )
                )
        for task in tasks:
            self._tasks[task.task_id] = task
        return tasks

    async def _attack_target(self, target: str, *, _depth: int = 0) -> dict[str, Any]:  # type: ignore[override]
        if not self._running:
            return {"status": "stopped", "state": self.get_state(target).to_dict()}
        state = self.get_state(target)
        logger.info(f"Starting attack lifecycle for {target} (pivot depth {_depth})")
        state.add_timeline_event("campaign_start", f"Attack campaign started against {target}")
        if is_local_target(state.target):
            await self._phase_local_takeover(state)
            await self._phase_validation(state)
            state.add_timeline_event("campaign_end", "Local-takeover campaign completed for local target")
            return {"status": "complete", "state": state.to_dict()}
        await self._phase_reconnaissance(state)
        if not state.recon_result or not state.recon_result.open_ports:
            logger.warning(f"No open ports on {target}, ending campaign")
            state.add_timeline_event("no_attack_surface", "No open ports found")
            return {"status": "no_attack_surface", "state": state.to_dict()}
        state.current_phase = AttackPhase.ENUMERATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        if self._adaptive_replan:
            await self._run_adaptive_rounds(state, _depth)
        else:
            await self._phase_exploitation(state)
            if not state.access_achieved and self._hard_target_max_rounds and state.aggression >= self._max_aggression:
                logger.info(
                    f"[HARD] {state.target} at max aggression with no access -- giving up (hard_target_max_rounds={self._hard_target_max_rounds})"
                )
                state.add_timeline_event(
                    "hard_target_give_up",
                    f"Target {state.target} reached max aggression ({state.aggression.value}) with no access; giving up.",
                    {"aggression": state.aggression.value},
                )
            if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
                await self._phase_privilege_escalation(state)
            if state.pivot_targets:
                await self._phase_lateral_movement(state, _depth)
        if self._persistence_enabled and state.access_achieved:
            await self._phase_persistence(state)  # type: ignore[attr-defined]
        await self._phase_validation(state)
        state.add_timeline_event("campaign_end", f"Attack campaign completed for {target}")
        return {"status": "complete", "state": state.to_dict()}
