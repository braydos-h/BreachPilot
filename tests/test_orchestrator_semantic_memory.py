"""D1: AutonomousOrchestrator wires SemanticMemoryManager as a cross-mission
lesson consumer — store_lesson fires on a confirmed module win.

The orchestrator is the missing campaign-level consumer: Flow A's exploit
loop already writes lessons via tools/exploit_agent/reflection.py:215-224 and
tools/exploit_mutator.py:138-180, but the orchestrator (which drives
multi-phase campaigns) never consumed the memory layer. These tests pin the
new wiring without touching a real DB/Ollama (mock the manager).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
)


class FakeSemantic:
    """Stand-in for SemanticMemoryManager — records store_lesson calls."""

    def __init__(self) -> None:
        self.lessons: list[dict[str, Any]] = []

    def store_lesson(self, *, target_signature, action_type, outcome, text, confidence=0.5, metadata=None) -> str:
        self.lessons.append(
            {
                "target_signature": target_signature,
                "action_type": action_type,
                "outcome": outcome,
                "text": text,
                "confidence": confidence,
                "metadata": metadata,
            }
        )
        return f"LSN-{len(self.lessons)}"


def _mission_config(tmp_path: Path) -> dict[str, Any]:
    return {
        "allowed_assets": ["10.0.0.50"],
        "disallowed_assets": [],
        "forbidden_actions": ["denial_of_service"],
        "risk_profile": "high_authorized_testing",
        "max_cycles": 10,
        "max_aggression": "maximum",
        "workspace": str(tmp_path),
    }


# ── Orchestrator wiring ────────────────────────────────────────────────────


def test_orchestrator_accepts_semantic_memory_kwarg(tmp_path: Path) -> None:
    """The orchestrator exposes a semantic_memory kwarg and threads it to the executor."""
    sem = FakeSemantic()
    orch = AutonomousOrchestrator(
        _mission_config(tmp_path),
        tmp_path / "ws",
        semantic_memory=sem,
    )
    assert orch._semantic_memory is sem
    # The executor is where execute() lives, so it must carry the manager too.
    assert orch._executor._semantic_memory is sem


def test_orchestrator_semantic_memory_default_none(tmp_path: Path) -> None:
    """Without the flag, no manager is built (opt-in)."""
    orch = AutonomousOrchestrator(_mission_config(tmp_path), tmp_path / "ws")
    assert orch._semantic_memory is None
    assert orch._executor._semantic_memory is None


def test_orchestrator_builds_manager_when_flag_set(tmp_path, monkeypatch) -> None:
    """When mission_config[semantic_memory] is true, the orchestrator builds one.

    The default-db + SemanticMemoryManager construction is patched so the test
    doesn't need a real DB or Ollama. The flag is opt-in (default false).
    """
    built = {}

    class _FakeManager:
        def __init__(self, *a, **kw):
            built["args"] = (a, kw)

    cfg = _mission_config(tmp_path)
    cfg["semantic_memory"] = True
    cfg["ollama"] = {"host": "http://localhost:11434", "embed_host": "http://localhost:11434"}
    cfg["embedding_model"] = "nomic-embed-text"

    # Patch the lazy imports inside __init__ via sys.modules.
    import sys
    import types

    fake_sem_mod = types.ModuleType("tools.semantic_memory")
    fake_sem_mod.SemanticMemoryManager = _FakeManager
    monkeypatch.setitem(sys.modules, "tools.semantic_memory", fake_sem_mod)
    fake_db_mod = types.ModuleType("db")
    fake_db_mod.get_default_db = lambda: object()
    monkeypatch.setitem(sys.modules, "db", fake_db_mod)

    orch = AutonomousOrchestrator(cfg, tmp_path / "ws")
    assert orch._semantic_memory is not None
    assert orch._executor._semantic_memory is orch._semantic_memory
    # The embed_host wins over host (local embeddings stay local).
    assert built["args"][1]["ollama_host"] == "http://localhost:11434"


# ── _record_lesson_on_success unit ─────────────────────────────────────────


def test_record_lesson_on_success_called_on_confirmed_win(tmp_path: Path) -> None:
    """A confirmed module success fires store_lesson with a distinct action_type.

    The action_type 'orchestrator:module_success' is isolated from the
    exploit-loop lessons ('reflection:exploit_loop') and the swarm reflection
    lessons ('reflection:strategy_shift') so downstream recall sees all three
    families but the Bayesian ExperienceStore stays untouched.
    """
    sem = FakeSemantic()
    executor = AttackModuleExecutor(semantic_memory=sem)
    task = AttackTask(
        task_id="ATK-00001",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
        aggression=AggressionLevel.NORMAL,
    )
    state = AttackState(target="10.0.0.50")
    result = {"status": "success", "shell_type": "reverse", "privilege_level": "user"}

    executor._record_lesson_on_success(task, state, result)

    assert len(sem.lessons) == 1
    lesson = sem.lessons[0]
    assert lesson["action_type"] == "orchestrator:module_success"
    assert lesson["outcome"] == "success"
    assert lesson["target_signature"] == "10.0.0.50"
    assert "SSHBruteForce" in lesson["text"]
    assert lesson["metadata"]["module"] == "SSHBruteForce"
    assert lesson["metadata"]["source"] == "autonomous_orchestrator"


def test_record_lesson_on_success_noop_without_manager() -> None:
    """No manager -> no call, no crash (the default opt-in state)."""
    executor = AttackModuleExecutor()
    task = AttackTask(
        task_id="ATK-00001",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
    )
    state = AttackState(target="10.0.0.50")
    # Should be a no-op (no exception, no lesson).
    executor._record_lesson_on_success(task, state, {"status": "success"})


def test_record_lesson_on_success_swallows_manager_exception() -> None:
    """A manager exception never breaks the campaign (best-effort write)."""

    class _Boom:
        def store_lesson(self, **kw):
            raise RuntimeError("ollama down")

    executor = AttackModuleExecutor(semantic_memory=_Boom())
    task = AttackTask(
        task_id="ATK-00001",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
    )
    state = AttackState(target="10.0.0.50")
    # Must not raise.
    executor._record_lesson_on_success(task, state, {"status": "success"})
