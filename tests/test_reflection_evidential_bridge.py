"""Phase 1.5: Reflection → ExperienceStore terminal-verdict bridge.

``_llm_reflect_inline`` accepts two new optional keyword params
(``experience_store`` and ``verdict_signal``) so a TERMINAL confirmed/refuted
hypothesis verdict from the Phase 1.2 OutcomeJudge can close the cross-mission
Bayesian loop. The bridge writes ONE evidence-grounded row via
``record_evidential_outcome`` with a DISTINCT ``action_type='reflection:verdict'``
so it cannot collide with the semantic lesson ('reflection:exploit_loop') or
operational exploit-action confidence rows.

Invariants verified here:
* A CONFIRMED terminal verdict -> exactly one ``record_evidential_outcome`` call
  with action_type='reflection:verdict', hypothesis_status='confirmed', and the
  evidence_refs threaded through.
* A REFUTED terminal verdict -> exactly one call with hypothesis_status='refuted'.
* A non-terminal (inconclusive/open/exhausted) verdict -> NO call.
* A partial reflection (verdict_signal=None, the default) -> NO call.
* Empty evidence_refs -> NO call (defense-in-depth; record_evidential_outcome
  itself rejects empty refs).
* No experience_store wired -> NO crash, NO call (graceful no-op).
* The semantic-lesson path (store_lesson, action_type='reflection:exploit_loop')
  is unchanged in every case — only the terminal-verdict case adds the extra
  Bayesian row.
* Existing callers that do not pass the new params stay green (default None).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.attack_planner import AttackPlan
from tools.exploit_agent import (
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    _llm_reflect_inline,
)

# ── Fakes ───────────────────────────────────────────────────────────────


class _FakeOllamaClient:
    """Fake Ollama client mirroring the real client.chat return shape."""

    def __init__(self, content: str):
        self._content = content
        self.chat_calls = 0

    def chat(self, model: str, **kwargs):  # noqa: ANN001, ANN201
        self.chat_calls += 1
        return {"message": {"content": self._content, "role": "assistant"}}


class _RecordingSemanticMemory:
    """Records store_lesson calls."""

    def __init__(self):
        self.lessons: list[dict[str, Any]] = []

    def store_lesson(self, **kwargs):  # noqa: ANN001, ANN201
        self.lessons.append(kwargs)
        return "fake-lesson-id"


class _RecordingExperienceStore:
    """Records record_evidential_outcome calls (the Bayesian bridge target)."""

    def __init__(self):
        self.evidential_calls: list[dict[str, Any]] = []
        self.record_outcome_calls: list[dict[str, Any]] = []

    def record_evidential_outcome(self, **kwargs):  # noqa: ANN001, ANN201
        self.evidential_calls.append(kwargs)
        return "fake-evidential-id"

    def record_outcome(self, *args, **kwargs):  # noqa: ANN001, ANN201
        self.record_outcome_calls.append({"args": args, "kwargs": kwargs})
        return "fake-outcome-id"


def _make_policy(tmp_path: Path, *, llm_reflection: bool = True, target_ip: str = "10.0.0.50"):
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=False,
        target_ip=target_ip,
        workspace_root=tmp_path,
        target_context={"llm_reflection": llm_reflection, "reflection_every_n_actions": 2},
    )
    policy = ExploitPolicy(settings, tmp_path)
    policy._locked_ip = target_ip
    policy._allowed_targets = [target_ip]
    return policy


def _messages_with_tool_results(*tool_msgs):
    msgs = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "begin recon"},
    ]
    msgs.extend(tool_msgs)
    return msgs


_VALID_REFLECTION_JSON = (
    "```json\n"
    "{\n"
    '  "patterns_identified": ["ssh banner grabbed", "anonymous ftp enabled"],\n'
    '  "why": "Service banners inconsistent with assumed target hardening.",\n'
    '  "new_hypothesis": "Target is a legacy appliance with default creds.",\n'
    '  "recommended_strategy_shift": "Try default credential pairs next.",\n'
    '  "confidence": 0.8\n'
    "}\n"
    "```"
)


def _confirmed_signal():
    return {
        "status": "confirmed",
        "confidence": 0.9,
        "evidence_refs": ["exploit_audit:10.0.0.50:att-001"],
    }


def _refuted_signal():
    return {
        "status": "refuted",
        "confidence": 0.85,
        "evidence_refs": ["tool_result:10.0.0.50:run_exploit_terminal"],
    }


# ── Terminal verdict → record_evidential_outcome ───────────────────────


@pytest.mark.asyncio
async def test_confirmed_verdict_triggers_evidential_bridge(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22,21"}
    )

    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp, verdict_signal=_confirmed_signal(),
    )

    # The LLM reflection ran.
    assert client.chat_calls == 1
    assert isinstance(result, dict)
    # Semantic lesson still written on the operational path.
    assert len(mem.lessons) == 1
    assert mem.lessons[0]["action_type"] == "reflection:exploit_loop"
    # AND the terminal-verdict bridge wrote one evidence-grounded Bayesian row.
    assert len(exp.evidential_calls) == 1
    call = exp.evidential_calls[0]
    assert call["target_signature"] == "10.0.0.50"
    assert call["action_type"] == "reflection:verdict"
    assert call["hypothesis_status"] == "confirmed"
    assert call["confidence"] == pytest.approx(0.9)
    assert call["evidence_refs"] == ["exploit_audit:10.0.0.50:att-001"]
    assert call["metadata"]["source"] == "exploit_loop_reflection"
    assert call["metadata"]["action_count"] == 4


@pytest.mark.asyncio
async def test_refuted_verdict_triggers_evidential_bridge(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22,21"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 6,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp, verdict_signal=_refuted_signal(),
    )

    assert len(exp.evidential_calls) == 1
    call = exp.evidential_calls[0]
    assert call["action_type"] == "reflection:verdict"
    assert call["hypothesis_status"] == "refuted"
    assert call["confidence"] == pytest.approx(0.85)
    assert call["evidence_refs"] == ["tool_result:10.0.0.50:run_exploit_terminal"]
    # Semantic lesson path unchanged.
    assert len(mem.lessons) == 1
    assert mem.lessons[0]["action_type"] == "reflection:exploit_loop"


# ── Non-terminal / partial reflections do NOT bridge ───────────────────


@pytest.mark.asyncio
async def test_inconclusive_verdict_does_not_bridge(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,
        verdict_signal={"status": "inconclusive", "confidence": 0.5,
                        "evidence_refs": ["tool_result:10.0.0.50:nmap_scan"]},
    )

    assert exp.evidential_calls == []
    # Semantic lesson still written.
    assert len(mem.lessons) == 1


@pytest.mark.asyncio
async def test_open_verdict_does_not_bridge(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,
        verdict_signal={"status": "open", "confidence": 0.5, "evidence_refs": ["x"]},
    )

    assert exp.evidential_calls == []


@pytest.mark.asyncio
async def test_exhausted_verdict_does_not_bridge(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,
        verdict_signal={"status": "exhausted", "confidence": 0.5, "evidence_refs": ["x"]},
    )

    assert exp.evidential_calls == []


@pytest.mark.asyncio
async def test_none_verdict_signal_does_not_bridge(tmp_path):
    """Default param (no verdict) — the historical caller path — stays green."""
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,  # verdict_signal intentionally omitted
    )

    assert exp.evidential_calls == []
    assert len(mem.lessons) == 1


@pytest.mark.asyncio
async def test_empty_evidence_refs_does_not_bridge(tmp_path):
    """Defense-in-depth: empty refs must not write a Bayesian row."""
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,
        verdict_signal={"status": "confirmed", "confidence": 0.9, "evidence_refs": []},
    )

    assert exp.evidential_calls == []


# ── Graceful no-op when experience_store is absent ─────────────────────


@pytest.mark.asyncio
async def test_no_experience_store_with_terminal_verdict_is_noop(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    # No experience_store passed; verdict_signal is terminal. Must not raise.
    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        verdict_signal=_confirmed_signal(),
    )

    assert isinstance(result, dict)
    assert len(mem.lessons) == 1


@pytest.mark.asyncio
async def test_experience_store_none_with_verdict_is_noop(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=None, verdict_signal=_confirmed_signal(),
    )
    assert isinstance(result, dict)


# ── Heuristic-only path (LLM reflection disabled) does not bridge ──────


@pytest.mark.asyncio
async def test_heuristic_only_path_does_not_bridge(tmp_path):
    """When llm_reflection is disabled the function returns the heuristic base
    before the bridge site — the terminal-verdict bridge is intentionally tied
    to the LLM reflection path (per the Phase 1.5 spec: "an LLM reflection's
    recommended_strategy_shift"). No Bayesian row is written."""
    policy = _make_policy(tmp_path, llm_reflection=False)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp, verdict_signal=_confirmed_signal(),
    )

    # Heuristic base returned; LLM never called; no bridge.
    assert client.chat_calls == 0
    assert isinstance(result, dict)
    assert "recommended_strategy_shift" in result
    assert exp.evidential_calls == []


# ── Status normalization (case-insensitive) ────────────────────────────


@pytest.mark.asyncio
async def test_verdict_status_is_case_insensitive(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    exp = _RecordingExperienceStore()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=exp,
        verdict_signal={"status": "CONFIRMED", "confidence": 0.9,
                        "evidence_refs": ["r1"]},
    )

    assert len(exp.evidential_calls) == 1
    assert exp.evidential_calls[0]["hypothesis_status"] == "confirmed"


# ── record_evidential_outcome failure never breaks the loop ────────────


@pytest.mark.asyncio
async def test_bridge_failure_does_not_break_loop(tmp_path):
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()

    class _BoomStore:
        def record_evidential_outcome(self, **kwargs):  # noqa: ANN001, ANN201
            raise RuntimeError("db locked")

    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22"}
    )

    # Must not raise even though the store blows up.
    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
        experience_store=_BoomStore(), verdict_signal=_confirmed_signal(),
    )
    assert isinstance(result, dict)
    assert "recommended_strategy_shift" in result
    # Semantic lesson still written (bridge failure is isolated).
    assert len(mem.lessons) == 1


# ── Existing callers without the new params stay green ─────────────────


@pytest.mark.asyncio
async def test_legacy_caller_without_new_params_stays_green(tmp_path):
    """The historical signature (no experience_store/verdict_signal) must work
    exactly as before — both params default to None and the bridge is a no-op."""
    policy = _make_policy(tmp_path)
    client = _FakeOllamaClient(_VALID_REFLECTION_JSON)
    mem = _RecordingSemanticMemory()
    plan = AttackPlan(target_ip="10.0.0.50")
    msgs = _messages_with_tool_results(
        {"role": "tool", "tool_name": "nmap_scan", "content": "open ports 22,21"}
    )

    result = await _llm_reflect_inline(
        client, "glm-5.2:cloud", msgs, plan, 4,
        semantic_memory=mem, policy=policy, target_ip="10.0.0.50",
    )

    assert client.chat_calls == 1
    assert "ssh banner grabbed" in result["what_worked"]
    assert "default credential" in result["recommended_strategy_shift"]
    assert len(mem.lessons) == 1
    assert mem.lessons[0]["action_type"] == "reflection:exploit_loop"
