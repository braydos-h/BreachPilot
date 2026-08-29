"""Independent oracle verification for benchmark trials.

The verifier is the ONLY source of ``oracle_verified_success``. It reuses the
graded eval's declarative check executors (:mod:`tools.eval_checks`) and flag
semantics (:func:`tools.eval_harness.verify_flag_check`) — the same loop the
``--eval`` suite trusts — so benchmark ground truth and eval ground truth are
one implementation, not two.

Agent claims, OutcomeJudge text, exit codes, and tool output NEVER decide a
flag here. An executor crash or a missing session degrades the affected flag
to FAIL/UNVERIFIED (fail-closed), never to a pass.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from tools.eval_checks import CheckExecutor, default_check_executor
from tools.eval_harness import FlagCheckResult, verify_flag_check

__all__ = ["VerificationOutcome", "IndependentVerifier", "default_verifier"]


@dataclass
class VerificationOutcome:
    """Result of independently verifying one trial against its oracle."""

    verified: bool = False
    flags: list[FlagCheckResult] = field(default_factory=list)
    flags_captured: int = 0
    flags_total: int = 0
    host_owned: bool = False
    detail: str = ""

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.flags]


def _host_owned_when_met(flags: list[FlagCheckResult], host_owned_when: Any) -> bool:
    """Mirror of eval_harness._host_owned_when_met over flag results."""
    captured = {f.flag_id for f in flags if f.passed}
    if isinstance(host_owned_when, (list, tuple)):
        required = [str(fid) for fid in host_owned_when]
        if not required:
            return bool(captured)
        return all(fid in captured for fid in required)
    if str(host_owned_when or "").strip().lower() == "all":
        return bool(flags) and len(captured) == len(flags)
    # "any" (and unrecognized values) fall back to the default.
    return bool(captured)


class IndependentVerifier:
    """Runs a scenario's oracle checks through the injected check executor.

    ``session`` / ``workspace`` / ``loop`` have the same meaning as
    :func:`tools.eval_checks.default_check_executor` — an MCP session (or a
    sync/async ``call_tool`` bridge) powers ``shell_command`` checks; HTTP and
    file checks verify without one. ``None`` session degrades shell checks to
    UNVERIFIED (fail-closed) rather than trusting the agent's word.
    """

    def __init__(
        self,
        scenario: Any,
        *,
        session: Any = None,
        workspace: Any = None,
        loop: Any = None,
        executor: CheckExecutor | None = None,
    ) -> None:
        self.scenario = scenario
        self._executor = executor
        self._session = session
        self._workspace = workspace
        self._loop = loop

    def _build_executor(self) -> CheckExecutor:
        if self._executor is not None:
            return self._executor
        return default_check_executor(
            session=self._session,
            workspace=self._workspace,
            loop=self._loop,
        )

    def verify_sync(self) -> VerificationOutcome:
        """Synchronous verification (call via ``asyncio.to_thread``)."""
        oracle = (self.scenario.oracle if self.scenario is not None else {}) or {}
        raw_flags = oracle.get("flags", []) or []
        flags = [f for f in raw_flags if isinstance(f, dict)]
        executor = self._build_executor()
        results: list[FlagCheckResult] = []
        for flag in flags:
            try:
                results.append(verify_flag_check(flag, executor))
            except Exception as exc:  # noqa: BLE001 -- a crashing check is a failed check
                flag_id = str(flag.get("id", "") or "unnamed_flag")
                results.append(
                    FlagCheckResult(flag_id=flag_id, passed=False, detail=f"verifier error: {exc}", check={})
                )
        captured = sum(1 for f in results if f.passed)
        owned = _host_owned_when_met(results, oracle.get("host_owned_when", "any"))
        detail = "; ".join(f"{f.flag_id}={'PASS' if f.passed else 'FAIL'}: {f.detail}" for f in results)
        return VerificationOutcome(
            verified=owned,
            flags=results,
            flags_captured=captured,
            flags_total=len(results),
            host_owned=owned,
            detail=detail,
        )

    async def verify(self) -> VerificationOutcome:
        """Async wrapper: verification runs on a worker thread (executor may block)."""
        return await asyncio.to_thread(self.verify_sync)


def default_verifier(
    scenario: Any,
    *,
    session: Any = None,
    workspace: Any = None,
    loop: Any = None,
) -> IndependentVerifier:
    """Build the standard verifier (same executor stack as the graded eval)."""
    return IndependentVerifier(scenario, session=session, workspace=workspace, loop=loop)
