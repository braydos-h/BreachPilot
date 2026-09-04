"""Service-specific task creation — extra exploit tasks per discovered service.

Extracted from ``AutonomousOrchestrator`` (see
``tools/campaign/orchestrator.py``) to keep the orchestrator under 500
lines. Bound onto ``AutonomousOrchestrator`` after its definition, so
``self._create_service_specific_tasks`` call sites and tests keep working
unchanged.
"""

from __future__ import annotations

from tools.campaign.state import AttackPhase, AttackState, AttackTask


def _create_service_specific_tasks(self, state: AttackState) -> list[AttackTask]:
    """Create additional tasks based on discovered services."""
    tasks: list[AttackTask] = []
    if not state.recon_result:
        return tasks

    for svc in state.recon_result.services:
        service = svc.service.lower()
        port = svc.port

        # SSH tasks
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

        # SMB tasks
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

        # HTTP/HTTPS tasks
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

        # FTP tasks
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

        # Redis tasks
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

        # Docker/K8s tasks
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

        # RDP tasks
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
