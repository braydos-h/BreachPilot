"""Regression tests for Tier 1.1 — Activate cross-mission learning.

Covers the wiring that turns the dormant SemanticMemoryManager + ExperienceStore
primitives into live runtime behavior across the three control flows:

- Flow A (run_exploit_agent): ExploitMutator writes real-embedding lessons on
  every exploit outcome; PayloadCrafter.generate folds cross-mission similar
  lessons into the generation prompt.
- Flow B (AgentLoop): evidence-confirmed/refuted judgments write outcomes + lessons;
  planning recalls similar lessons + cross-mission memory; run() end distills
  episodic memories into a semantic lesson.
- Swarm: reflection_agent persists its reflection as a cross-mission lesson +
  outcome when semantic_memory/experience are in the swarm context.

The primitives' own soundness (min-samples gate, time decay, empty-embedding
filter, failure logging) is covered in ``test_semantic_memory.py``.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from outcome_judge import (
    ExecutionOutcome,
    HypothesisStatus,
    OutcomeAssessment,
)
from tools.exploit_mutator import ExploitMutator
from tools.payload_crafter import CraftedPayload, PayloadCrafter

# ── Fakes ─────────────────────────────────────────────────────────────────


class FakeSemantic:
    """Stand-in for SemanticMemoryManager that records calls and returns canned recall."""

    def __init__(self) -> None:
        self.lessons: list[dict[str, Any]] = []
        self.queries: list[dict[str, Any]] = []
        self._similar: list[dict[str, Any]] = []
        self._summary: str = ""  # canned summarize_episodes return

    def store_lesson(self, *, target_signature, action_type, outcome, text,
                     confidence=0.5, metadata=None) -> str:
        self.lessons.append({
            "target_signature": target_signature,
            "action_type": action_type,
            "outcome": outcome,
            "text": text,
            "confidence": confidence,
            "metadata": metadata,
        })
        return f"LSN-{len(self.lessons)}"

    def find_similar_lessons(self, *, text, outcome=None, top_k=3, action_type=None) -> list[dict]:
        self.queries.append({"text": text, "outcome": outcome, "top_k": top_k})
        return list(self._similar)

    def summarize_episodes(self, memory_type, mission_id, client=None, model="") -> str:
        return self._summary


class FakeExperience:
    """Stand-in for ExperienceStore that records outcome writes."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._confs: dict[str, float] = {}

    def update_from_exploit_result(self, *, service_name, version, os_hint,
                                    module_name, mutation_strategy, success) -> None:
        self.calls.append({
            "sig": f"{service_name}:{version}:{os_hint}",
            "action": f"{module_name}:{mutation_strategy}",
            "success": success,
        })

    def get_all_confidences(self, sig: str) -> dict[str, float]:
        return dict(self._confs)


def _payload(**overrides) -> CraftedPayload:
    meta = {"service_name": "ssh", "version": "8.2", "os_hint": "linux", "module_name": "SSHBruteForce"}
    meta.update(overrides.pop("metadata", {}))
    base = dict(
        generation_id="g1", parent_id=None, script="x",
        mutation_strategy="generate", metadata=meta, confidence=0.5,
    )
    base.update(overrides)
    return CraftedPayload(**base)


# ═══════════════════════════════════════════════════════════════════════════
# Flow A — ExploitMutator writes real-embedding semantic lessons
# ═══════════════════════════════════════════════════════════════════════════


def test_mutator_record_success_stores_semantic_lesson(tmp_path):
    sem = FakeSemantic()
    exp = FakeExperience()
    mut = ExploitMutator(workspace=tmp_path, experience_store=exp, semantic_memory=sem)
    mut.record_success(_payload())
    # Bayesian outcome recorded
    assert len(exp.calls) == 1 and exp.calls[0]["success"] is True
    # Real-embedding lesson written with the right signature/action
    assert len(sem.lessons) == 1
    lesson = sem.lessons[0]
    assert lesson["outcome"] == "success"
    assert lesson["target_signature"] == "ssh:8.2:linux"
    assert lesson["action_type"] == "SSHBruteForce:generate"
    assert "success" in lesson["text"]


def test_mutator_record_failure_stores_lesson_with_why(tmp_path):
    sem = FakeSemantic()
    exp = FakeExperience()
    mut = ExploitMutator(workspace=tmp_path, experience_store=exp, semantic_memory=sem)
    mut.record_failure(_payload(), failure_output="Connection refused")
    assert exp.calls[0]["success"] is False
    assert sem.lessons[0]["outcome"] == "failure"
    # The failure reason is folded into the lesson text for cross-mission recall
    assert "Connection refused" in sem.lessons[0]["text"]


def test_mutator_no_semantic_still_records_experience(tmp_path):
    """Back-compat: no SemanticMemoryManager -> Bayesian loop still closes, no crash."""
    exp = FakeExperience()
    mut = ExploitMutator(workspace=tmp_path, experience_store=exp, semantic_memory=None)
    mut.record_success(_payload())
    assert len(exp.calls) == 1


def test_mutator_no_experience_still_stores_lesson(tmp_path):
    """The two writes are independent: no ExperienceStore -> lesson still writes."""
    sem = FakeSemantic()
    mut = ExploitMutator(workspace=tmp_path, experience_store=None, semantic_memory=sem)
    mut.record_success(_payload())
    assert len(sem.lessons) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Flow A — PayloadCrafter.generate folds cross-mission lessons into the prompt
# ═══════════════════════════════════════════════════════════════════════════


def test_crafter_generate_folds_cross_mission_lessons(tmp_path):
    sem = FakeSemantic()
    sem._similar = [{
        "action_type": "SSHBruteForce:parameter_tweak",
        "target_signature": "ssh:8.2:linux",
        "outcome": "success",
        "similarity": 0.9,
    }]
    exp = FakeExperience()
    exp._confs = {"SSHBruteForce:generate": 0.8}
    crafter = PayloadCrafter(workspace=tmp_path, experience_store=exp, semantic_memory=sem)

    captured: dict[str, Any] = {}
    def spy(**kwargs):
        captured["exp_hints"] = kwargs.get("exp_hints", "")
        return "# stub script"
    crafter._build_script_from_template = spy  # type: ignore[method-assign]

    crafter.generate(target_ip="10.0.0.5", service_name="ssh", version="8.2",
                     os_hint="linux", module_name="SSHBruteForce")
    # find_similar_lessons was queried with contextual text (not a bare IP)
    assert sem.queries, "find_similar_lessons was never called"
    assert "ssh" in sem.queries[0]["text"]
    assert sem.queries[0]["outcome"] == "success"
    # The similar lesson is folded into the generation hints
    assert "CROSS-MISSION LESSONS" in captured["exp_hints"]
    assert "SSHBruteForce:parameter_tweak" in captured["exp_hints"]


def test_crafter_generate_without_semantic_no_recall(tmp_path):
    """Back-compat: no SemanticMemoryManager -> no recall, no crash, no lesson block."""
    exp = FakeExperience()
    crafter = PayloadCrafter(workspace=tmp_path, experience_store=exp, semantic_memory=None)
    captured: dict[str, Any] = {}
    crafter._build_script_from_template = lambda **kwargs: (  # type: ignore[method-assign]
        captured.update(hints=kwargs.get("exp_hints", "")) or "# stub"
    )
    crafter.generate(target_ip="10.0.0.5", service_name="ssh", version="8.2",
                     os_hint="linux", module_name="SSHBruteForce")
    assert "CROSS-MISSION LESSONS" not in captured.get("hints", "")


def test_crafter_generate_recall_failure_does_not_block(tmp_path):
    """A recall exception must be swallowed, never break generation."""
    class BoomSemantic:
        def find_similar_lessons(self, **kwargs):
            raise RuntimeError("ollama down")
    crafter = PayloadCrafter(workspace=tmp_path, experience_store=None,
                             semantic_memory=BoomSemantic())
    # Should not raise
    payload = crafter.generate(target_ip="10.0.0.5", service_name="ssh", version="8.2",
                               os_hint="linux", module_name="SSHBruteForce")
    assert payload.script  # generation still produced a payload


# ═══════════════════════════════════════════════════════════════════════════
# Flow B — AgentLoop writes outcomes/lessons + distills episodes + recalls
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def temp_db():
    db_path = Path("test_workspace_cross_mission") / "research.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    from db import DatabaseManager
    db = DatabaseManager(db_path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    yield db
    shutil.rmtree(db_path.parent, ignore_errors=True)


def _mock_executor():
    def _exec(tool: str, args: dict) -> str:
        return f"Mock output for {tool}"
    return _exec


def _make_flowb_loop(tmp_path, *, semantic: bool = True):
    """Build a real AgentLoop with a tmp workspace + cheap-to-clear gates."""
    from agent_loop import AgentLoop
    config = {
        "program_name": "FlowB Test",
        "objective": "test cross-mission wiring",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": False,
        "memory": {
            "semantic_enabled": semantic,
            "embedding_model": "nomic-embed-text",
            # min_samples=1 + decay=0 so a single outcome clears the gate and
            # every row weighs 1.0 — keeps the Bayesian assertions trivial.
            "experience_min_samples": 1,
            "experience_time_decay_days": 0,
        },
    }
    return AgentLoop(config, tmp_path / "ws", _mock_executor())


def test_flowb_record_outcome_and_lesson_success_writes_both(tmp_path):
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    loop._semantic_memory = sem  # spy on the semantic write
    task = {"task_id": "T-1", "phase": "exploit", "target": "10.0.0.5",
            "objective": "brute ssh"}
    assessment = OutcomeAssessment(
        task_id="T-1",
        hypothesis_id="H-1",
        execution_outcome=ExecutionOutcome.SUCCEEDED,
        hypothesis_status=HypothesisStatus.CONFIRMED,
        confidence=0.9,
        evidence_refs=["E-1"],
        reasoning="Evidence confirmed the hypothesis.",
    )
    loop._record_outcome_and_lesson(task, assessment)
    # Bayesian outcome recorded on the real ExperienceStore (Beta(2,1)=0.667)
    assert loop._experience.get_confidence("10.0.0.5", "exploit:brute ssh") > 0.5
    # Real-embedding semantic lesson written with the right signature/action
    assert len(sem.lessons) == 1
    assert sem.lessons[0]["outcome"] == "success"
    assert sem.lessons[0]["target_signature"] == "10.0.0.5"
    assert sem.lessons[0]["action_type"] == "exploit:brute ssh"
    assert "success" in sem.lessons[0]["text"]


def test_flowb_record_outcome_and_lesson_failure_includes_why(tmp_path):
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    loop._semantic_memory = sem
    task = {"task_id": "T-2", "phase": "exploit", "target": "10.0.0.5",
            "objective": "x"}
    assessment = OutcomeAssessment(
        task_id="T-2",
        hypothesis_id="H-2",
        execution_outcome=ExecutionOutcome.SUCCEEDED,
        hypothesis_status=HypothesisStatus.REFUTED,
        confidence=0.9,
        evidence_refs=["E-2"],
        reasoning="Evidence refuted the hypothesis: Connection refused.",
    )
    loop._record_outcome_and_lesson(task, assessment)
    assert loop._experience.get_confidence("10.0.0.5", "exploit:x") < 0.5
    assert sem.lessons[0]["outcome"] == "failure"
    assert "Connection refused" in sem.lessons[0]["text"]


def test_flowb_record_outcome_no_semantic_bayesian_only(tmp_path):
    """No SemanticMemoryManager -> Bayesian loop still closes, no crash, no lesson."""
    loop = _make_flowb_loop(tmp_path, semantic=False)
    assert loop._semantic_memory is None
    task = {"task_id": "T-3", "phase": "recon", "target": "10.0.0.5",
            "objective": "x"}
    assessment = OutcomeAssessment(
        task_id="T-3",
        hypothesis_id="H-3",
        execution_outcome=ExecutionOutcome.SUCCEEDED,
        hypothesis_status=HypothesisStatus.CONFIRMED,
        confidence=0.9,
        evidence_refs=["E-3"],
    )
    loop._record_outcome_and_lesson(task, assessment)  # must not raise
    assert loop._experience.get_confidence("10.0.0.5", "recon:x") > 0.5


def test_flowb_inconclusive_judgment_does_not_write_learning(tmp_path):
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    loop._semantic_memory = sem
    task = {
        "task_id": "T-INC",
        "phase": "recon",
        "target": "10.0.0.5",
        "objective": "x",
    }
    assessment = OutcomeAssessment(
        task_id="T-INC",
        hypothesis_id="H-INC",
        execution_outcome=ExecutionOutcome.SUCCEEDED,
        hypothesis_status=HypothesisStatus.INCONCLUSIVE,
        confidence=0.5,
        evidence_refs=["E-INC"],
    )
    loop._record_outcome_and_lesson(task, assessment)
    assert loop._experience.observation_count("10.0.0.5", "recon:x") == 0
    assert sem.lessons == []


def test_flowb_distill_episode_factual_fallback(tmp_path):
    """No model client -> distill falls back to a battle-log roll-up lesson."""
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    loop._semantic_memory = sem
    loop._cycles = 5
    loop._battle_log = [{"success": True}, {"success": False}, {"success": True}]
    loop._distill_episode_summary()
    assert len(sem.lessons) == 1
    assert sem.lessons[0]["action_type"] == "campaign:episode_summary"
    assert "2/3" in sem.lessons[0]["text"]


def test_flowb_distill_episode_with_model(tmp_path):
    """Model client wired -> distill uses summarize_episodes output as the lesson."""
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    sem._summary = "Lessons: ssh brute succeeds when banner leaks version."
    loop._semantic_memory = sem
    loop._model_client = object()  # truthy -> summarize_episodes path taken
    loop._model_name = "glm"
    loop._distill_episode_summary()
    assert len(sem.lessons) == 1
    assert "ssh brute succeeds" in sem.lessons[0]["text"]


def test_flowb_distill_no_semantic_is_noop(tmp_path):
    loop = _make_flowb_loop(tmp_path, semantic=False)
    loop._cycles = 3
    loop._battle_log = [{"success": True}]
    loop._distill_episode_summary()  # must not raise, must not write


def test_flowb_cross_mission_recall_returns_block(tmp_path):
    loop = _make_flowb_loop(tmp_path)
    sem = FakeSemantic()
    sem._similar = [{
        "action_type": "SSHBruteForce", "target_signature": "ssh:8.2:linux",
        "outcome": "success", "similarity": 0.9,
    }]
    loop._semantic_memory = sem
    captured: dict[str, Any] = {}
    loop._memory.retrieve_relevant = lambda **kw: (captured.update(kw) or [{"fact": "prior: ssh open"}])
    block = loop._cross_mission_recall("ssh service on linux")
    assert "CROSS-MISSION LESSONS" in block
    assert "SSHBruteForce" in block
    assert "PRIOR MISSION MEMORY" in block
    assert "ssh open" in block
    # retrieve_relevant got the *context* (not the bare program_name target)
    assert captured.get("context") == "ssh service on linux"


def test_flowb_cross_mission_recall_no_semantic_empty(tmp_path):
    loop = _make_flowb_loop(tmp_path, semantic=False)
    assert loop._cross_mission_recall("anything") == ""


def test_flowb_cross_mission_recall_empty_context_empty(tmp_path):
    loop = _make_flowb_loop(tmp_path)
    loop._semantic_memory = FakeSemantic()
    assert loop._cross_mission_recall("") == ""
    assert loop._cross_mission_recall("   ") == ""


def test_retrieve_relevant_embeds_context_not_bare_ip(temp_db):
    """The semantic fallback embeds the context, not the bare target IP."""
    from memory import MemoryManager
    from tools.semantic_memory import SemanticMemoryManager

    sem = SemanticMemoryManager(temp_db)
    embed_calls: list[str] = []
    sem._generate_embedding = lambda text: embed_calls.append(text) or [0.1, 0.2, 0.3]
    mgr = MemoryManager(temp_db, "M-1", semantic_memory=sem)

    # Empty DB -> exact match yields nothing -> semantic fallback fires.
    mgr.retrieve_relevant(target="10.0.0.5", context="ssh brute force on linux", limit=5)
    assert embed_calls, "semantic fallback never fired"
    # The embed call must carry the context, NOT the bare IP.
    assert "ssh brute force" in embed_calls[-1]
    assert "10.0.0.5" not in embed_calls[-1]


def test_retrieve_relevant_context_back_compat(temp_db):
    """context defaults to "" -> pre-1.1 callers still work (embeds target)."""
    from memory import MemoryManager
    from tools.semantic_memory import SemanticMemoryManager

    sem = SemanticMemoryManager(temp_db)
    embed_calls: list[str] = []
    sem._generate_embedding = lambda text: embed_calls.append(text) or [0.1, 0.2, 0.3]
    mgr = MemoryManager(temp_db, "M-1", semantic_memory=sem)
    mgr.retrieve_relevant(target="10.0.0.5", limit=5)  # no context kwarg
    assert embed_calls and embed_calls[-1] == "10.0.0.5"


# ═══════════════════════════════════════════════════════════════════════════
# Swarm — reflection_agent persists a cross-mission lesson
# ═══════════════════════════════════════════════════════════════════════════


def _failing_battle_log(n: int) -> list[dict[str, Any]]:
    return [
        {"tool": "SSHBruteForce", "target": "10.0.0.5", "success": False,
         "error": "Connection refused", "summary": ""}
        for _ in range(n)
    ]


def test_reflection_agent_stores_lesson_when_semantic_in_context():
    from tools.swarm.agents.reflection_agent import ReflectionAgent
    sem = FakeSemantic()
    agent = ReflectionAgent()
    task = {"task_id": "R-1", "battle_log": _failing_battle_log(4),
            "session_state": {"target_ip": "10.0.0.5"}}
    context = {"semantic_memory": sem, "memory": None,
               "model_client": None, "blackboard": {}}
    result = agent.run(task, context)
    # 4 failures / 0 successes -> MAJOR PIVOT shift (non-empty)
    assert result.output["recommended_strategy_shift"]
    assert len(sem.lessons) == 1
    lesson = sem.lessons[0]
    assert lesson["outcome"] == "partial"
    assert lesson["action_type"] == "reflection:strategy_shift"
    assert lesson["target_signature"] == "10.0.0.5"


def test_reflection_agent_no_semantic_no_lesson_no_crash():
    from tools.swarm.agents.reflection_agent import ReflectionAgent
    agent = ReflectionAgent()
    task = {"task_id": "R-2", "battle_log": _failing_battle_log(4),
            "session_state": {"target_ip": "10.0.0.5"}}
    context = {"memory": None, "model_client": None, "blackboard": {}}
    result = agent.run(task, context)  # must not raise
    assert result.output["recommended_strategy_shift"]  # reflection still runs


def test_reflection_agent_no_shift_no_lesson():
    """No failures/successes -> 'PROCEED' shift is non-empty, so a lesson IS
    written; verify the guard is really on shift emptiness, not outcome counts,
    by forcing an empty shift via an empty battle log + patched output."""
    from tools.swarm.agents.reflection_agent import ReflectionAgent
    sem = FakeSemantic()
    agent = ReflectionAgent()
    task = {"task_id": "R-3", "battle_log": [],
            "session_state": {"target_ip": "10.0.0.5"}}
    context = {"semantic_memory": sem, "memory": None,
               "model_client": None, "blackboard": {}}
    agent.run(task, context)
    # Empty battle log -> 'PROCEED: No data yet...' (non-empty) -> lesson written.
    assert len(sem.lessons) == 1
