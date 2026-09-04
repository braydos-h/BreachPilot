"""Task-batch execution — concurrent dispatch, retry, prerequisite recovery.

Extracted from ``AutonomousOrchestrator`` (see
``tools/campaign/orchestrator.py``) to keep the orchestrator under 500
lines. The functions below are bound onto ``AutonomousOrchestrator`` after
its definition, so ``self._execute_task_batch`` call sites and tests keep
working unchanged. Each takes the orchestrator instance as an untyped first
arg so the body stays verbatim.
"""

from __future__ import annotations

import asyncio
import re

from tools.campaign.state import AttackPhase, AttackState, AttackTask, RetryEngine, TaskStatus
from tools.logging_setup import get_logger

logger = get_logger()


async def _execute_task_batch(self, tasks: list[AttackTask], state: AttackState) -> None:
    """Execute a batch of tasks with concurrency control."""
    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent attacks
    # Capability-upgrade (§9): per-batch guard so each failing task
    # schedules at most one prerequisite-recovery task. Cleared per batch.
    prereq_scheduled: set[str] = set()

    async def run_task(task: AttackTask) -> None:
        # Bug #6: the retry used to recurse (``await run_task(task)``) from
        # *inside* the ``async with semaphore`` block. The recursive call
        # had to re-acquire the semaphore while the outer frame still held
        # its slot, so with 3 concurrent failing retryable tasks every
        # slot was occupied by an outer frame waiting on an inner frame
        # that could never get a slot — a classic deadlock. The loop
        # below releases the semaphore (the ``async with`` exits) before
        # sleeping/retrying, so retries re-acquire a slot cleanly.
        while True:
            async with semaphore:
                result = await self._executor.execute(task, state)

            # Handle retry logic — semaphore is released here, so other
            # tasks can run during the backoff sleep.
            if not result.get("success") and not result.get("blocked"):
                # Capability-upgrade (§9): prerequisite-driven composition.
                # If the failure classifies as PREREQUISITE_MISSING, look
                # up a producer module for the missing artifact and run it
                # inline before retrying the original. Bounded by the
                # per-batch set + the campaign-level ``_prereq_recovery_cap``.
                # Recovery tasks are themselves exempt from re-scheduling
                # (created_from tag) so a missing chain cannot recurse.
                if task.created_from != "recovery:prerequisite" and task.task_id not in prereq_scheduled:
                    prereq_task = self._maybe_schedule_prereq(
                        task,
                        state,
                        result.get("error", ""),
                    )
                    if prereq_task is not None:
                        prereq_scheduled.add(task.task_id)
                        await run_task(prereq_task)
                if RetryEngine.should_retry(
                    task.module_name,
                    result.get("error", ""),
                    task.retry_count,
                    task.max_retries,
                ):
                    task.retry_count += 1
                    task.parameters.update(RetryEngine.get_retry_parameters(task.module_name, task.retry_count))
                    task.status = TaskStatus.RETRYING
                    logger.info(f"Retrying {task.module_name} with modified parameters (attempt {task.retry_count})")
                    await asyncio.sleep(2**task.retry_count)  # Exponential backoff
                    continue
            return

    await asyncio.gather(*[run_task(t) for t in tasks], return_exceptions=True)


# ── Prerequisite-driven composition (§9) ───────────────────────────────

# Maps a PREREQUISITE_MISSING error text to the candidate artifact kinds a
# producer module could supply. Ordered by specificity; the first kind
# with a producer wins. Kinds mirror the ``produces`` metadata modules
# actually declare (credentials/hash_artifact/foothold/shell/webshell/
# high_priv/admin_priv).
_PREREQ_KIND_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"credential|creds|password|hash", re.IGNORECASE), ("credentials", "hash_artifact")),
    (re.compile(r"foothold|session|\bshell\b|webshell", re.IGNORECASE), ("foothold", "shell", "webshell")),
    (re.compile(r"admin|root|privilege|high_priv|admin_priv", re.IGNORECASE), ("high_priv", "admin_priv")),
)


def _prereq_artifact_kinds(self, error: str) -> list[str]:
    """Derive candidate artifact kinds from a PREREQUISITE_MISSING error."""
    kinds: list[str] = []
    for pat, ks in _PREREQ_KIND_PATTERNS:
        if pat.search(error or ""):
            kinds.extend(ks)
    return kinds


def _maybe_schedule_prereq(
    self,
    task: AttackTask,
    state: AttackState,
    error: str,
) -> AttackTask | None:
    """Schedule a producer module for a missing prerequisite, if one exists.

    Returns the new AttackTask (also registered in ``self._tasks``) or
    None when the failure is not a missing-prerequisite signal, no
    producer module is found, or the campaign-level recovery cap is hit.
    Bounded: one prereq task per failing task (enforced by the caller's
    ``prereq_scheduled`` set) and ``self._prereq_recovery_cap`` total.
    """
    try:
        from tools.failure_taxonomy import FailureClass, classify_failure

        fc = classify_failure(error)
    except Exception:  # noqa: BLE001 -- taxonomy import must never break the batch
        return None
    if fc != FailureClass.PREREQUISITE_MISSING:
        return None
    kinds = self._prereq_artifact_kinds(error)
    if not kinds:
        return None
    if self._prereq_tasks_added >= self._prereq_recovery_cap:
        return None
    # Candidates via the established seam (shim find_producers, which
    # tests mock and plugins extend), ordered cheapest/read-only-first
    # with ctx-satisfied prerequisites ahead (graph.rank_producers).
    try:
        import tools.autonomous_orchestrator as _ao_shim3  # type: ignore[import]

        _find_producers = getattr(_ao_shim3, "find_producers", None)
    except Exception:  # noqa: BLE001 -- seam lookup must never break recovery
        _find_producers = None
    if _find_producers is None:
        from tools.attack_modules import find_producers as _find_producers  # type: ignore[import]

    def _ranked(kind: str) -> list:
        cands = [m for m in _find_producers(kind) if m.name != task.module_name]
        try:
            from tools.attack_modules.graph import rank_producers as _rank_producers

            try:
                _ctx = self._module_context(state)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                _ctx = None
            return _rank_producers(kind, _ctx, exclude=task.module_name, modules=cands)
        except Exception:  # noqa: BLE001 -- ranking must never break recovery
            return cands

    for kind in kinds:
        for mod in _ranked(kind):
            if mod.name == task.module_name:
                continue  # don't recurse into the failing module
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
                f"[RECOVERY] Scheduled prerequisite producer {mod.name} "
                f"(produces {kind}) for failed {task.module_name} ({error!r})"
            )
            return prereq_task
    return None


async def _retry_failed_modules(self, state: AttackState) -> None:
    """Retry failed modules with escalated aggression."""
    all_failed = set(state.failed_attempts.keys()) - set(state.successful_exploits)
    # ponytail: drop modules over the campaign-level failure cap so a
    # structurally-failing exploit (e.g. Log4jRCE vs a non-vulnerable
    # target) doesn't get re-queued forever on every aggression step.
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
