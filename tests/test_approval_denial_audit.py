"""Regression tests for approve_only denial auditing (Phase 1 defect 5).

Every non-approved exit of ``ExploitPolicy.approve_action`` must write a
denial row through the EXISTING chained writer (``record`` -> the
tamper-evident ``exploit_audit.jsonl`` hash chain). Previously only the
READ_ONLY branch recorded, so an approve_only denial (operator says no,
aborted prompt, exhausted budget) left NO evidence in the audit chain.

These tests assert, per denial exit:
1. ``approve_action`` returns False (unchanged contract).
2. An audit row exists with ``approved=False``, ``status='denied'`` (or the
   specific status) and the human/operator decision source.
3. ``verify_audit_chain`` passes on the resulting JSONL (the denial rows are
   properly chained, not orphaned).
4. Successful approvals and budget accounting are unchanged (no double
   records, denials do not consume the command budget).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.exploit_agent import (
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    verify_audit_chain,
)

AUDIT = "exploit_audit.jsonl"


def _settings(
    tmp_path: Path,
    permission: ExploitPermission = ExploitPermission.APPROVE_ONLY,
    target: str = "10.0.0.50",
) -> ExploitSettings:
    return ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=permission,
        attack_mode=False,
        target_ip=target,
        workspace_root=tmp_path,
    )


def _audit_rows(tmp_path: Path) -> list[dict]:
    path = tmp_path / AUDIT
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ── 1. Async approval provider: operator denial ──────────────────────────────


class _DenyProvider:
    async def approve(self, action, command, detail, target):  # noqa: ANN001
        return False


class _AllowThenDenyProvider:
    def __init__(self) -> None:
        self.calls = 0

    async def approve(self, action, command, detail, target):  # noqa: ANN001
        self.calls += 1
        return self.calls == 1


@pytest.mark.asyncio
async def test_provider_denial_recorded_and_chained(tmp_path: Path):
    """approve_only + provider denial -> False, one 'denied' row from the
    operator, and a valid hash chain."""
    policy = ExploitPolicy(_settings(tmp_path), tmp_path, approval_provider=_DenyProvider())
    assert await policy.approve_action("run_exploit_terminal", "id") is False

    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    d = denials[0]
    assert d.approved is False
    assert d.approved_by == "operator"
    assert d.action == "run_exploit_terminal"
    assert "operator denied" in d.detail
    assert d.hash, "denial row must carry a chain hash"

    rows = _audit_rows(tmp_path)
    assert rows and rows[0]["status"] == "denied"
    assert rows[0]["approved"] is False
    ok, why = verify_audit_chain(tmp_path / AUDIT)
    assert ok, why


@pytest.mark.asyncio
async def test_provider_approval_then_denial(tmp_path: Path):
    """Approve one action, deny the next: the approval writes no policy row
    (the runner owns completed/error rows), the denial writes exactly one, and
    the denial does not consume the command budget."""
    policy = ExploitPolicy(_settings(tmp_path), tmp_path, approval_provider=_AllowThenDenyProvider())
    assert await policy.approve_action("run_exploit_terminal", "id") is True
    assert policy._command_count == 1
    assert not policy.read_audit_records(), "approved actions write no policy rows"
    assert await policy.approve_action("run_exploit_terminal", "whoami") is False
    assert policy._command_count == 1, "a denial must not consume the budget"

    records = policy.read_audit_records()
    assert len(records) == 1
    assert records[0].status == "denied"
    ok, why = verify_audit_chain(tmp_path / AUDIT)
    assert ok, why


# ── 2. Legacy interactive prompt ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_interactive_prompt_denial_recorded(tmp_path: Path):
    """A non-ALLOW answer is recorded as an operator denial."""
    policy = ExploitPolicy(_settings(tmp_path), tmp_path, prompt_func=lambda _msg: "no")
    assert await policy.approve_action("run_exploit_terminal", "id") is False

    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    assert denials[0].approved is False
    assert denials[0].approved_by == "operator"
    ok, _ = verify_audit_chain(tmp_path / AUDIT)
    assert ok


@pytest.mark.asyncio
async def test_interactive_prompt_allow_writes_no_denial(tmp_path: Path):
    """The happy path stays unchanged: ALLOW <host> approves, no denial rows,
    and the runner (not the policy) owns the completed/error rows."""
    policy = ExploitPolicy(_settings(tmp_path), tmp_path, prompt_func=lambda _msg: "ALLOW 10.0.0.50")
    assert await policy.approve_action("run_exploit_terminal", "id") is True
    assert policy._command_count == 1
    assert not [r for r in policy.read_audit_records() if r.status == "denied"]


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
async def test_interactive_prompt_abort_recorded(tmp_path: Path, exc: type[BaseException]):
    """EOF/KeyboardInterrupt exits record the abort, then return False — the
    exception must not be swallowed into an approval."""

    def raising_prompt(_msg: str) -> str:
        raise exc()

    policy = ExploitPolicy(_settings(tmp_path), tmp_path, prompt_func=raising_prompt)
    assert await policy.approve_action("run_exploit_terminal", "id") is False

    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    assert "aborted" in denials[0].detail
    assert denials[0].approved is False
    ok, _ = verify_audit_chain(tmp_path / AUDIT)
    assert ok


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
async def test_provider_abort_recorded(tmp_path: Path, exc: type[BaseException]):
    """The async provider raising EOF/KeyboardInterrupt is recorded too."""

    class _AbortProvider:
        async def approve(self, action, command, detail, target):  # noqa: ANN001
            raise exc()

    policy = ExploitPolicy(_settings(tmp_path), tmp_path, approval_provider=_AbortProvider())
    assert await policy.approve_action("run_exploit_terminal", "id") is False

    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    assert "aborted" in denials[0].detail
    ok, _ = verify_audit_chain(tmp_path / AUDIT)
    assert ok


# ── 3. Budget exhaustion (symmetric evidence, all modes) ─────────────────────


@pytest.mark.asyncio
async def test_budget_exhaustion_denial_recorded(tmp_path: Path):
    """An exhausted command budget records a 'denied' row with the budget
    detail — symmetric evidence with the human denials."""
    settings = _settings(tmp_path)
    policy = ExploitPolicy(settings, tmp_path, approval_provider=_DenyProvider())
    policy._command_count = settings.max_commands_per_session  # exhaust the budget

    assert await policy.approve_action("run_exploit_terminal", "id") is False
    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    assert "budget" in denials[0].detail
    ok, _ = verify_audit_chain(tmp_path / AUDIT)
    assert ok


@pytest.mark.asyncio
async def test_budget_exhaustion_denial_recorded_full_access(tmp_path: Path):
    """Same symmetric evidence on the full_access path (gate=None so the
    mission-scope check is skipped and the budget check is what fires)."""
    settings = _settings(tmp_path, permission=ExploitPermission.FULL_ACCESS)
    policy = ExploitPolicy(settings, tmp_path)
    policy._command_count = settings.max_commands_per_session

    assert await policy.approve_action("run_exploit_terminal", "id") is False
    denials = [r for r in policy.read_audit_records() if r.status == "denied"]
    assert len(denials) == 1
    assert "budget" in denials[0].detail


# ── 4. Chain integrity across mixed outcomes ─────────────────────────────────


@pytest.mark.asyncio
async def test_mixed_outcomes_form_one_chain(tmp_path: Path):
    """completed-style records and denial rows interleave into ONE valid
    chain (the MCP tool layer's unchained rows are exercised in
    tests/test_audit_chain.py)."""
    policy = ExploitPolicy(_settings(tmp_path), tmp_path, approval_provider=_DenyProvider())
    await policy.record(action="run_exploit_terminal", command="echo done", status="completed")
    assert await policy.approve_action("run_exploit_terminal", "whoami") is False

    records = policy.read_audit_records()
    assert [r.status for r in records] == ["completed", "denied"]
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.hash
    ok, why = verify_audit_chain(tmp_path / AUDIT)
    assert ok, why
