"""MemoryService facade over the per-attempt window, cross-mission store, and checkpoint / resume (split from tools.memory_service)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING, Any

from db import DatabaseManager
from tools.goal_suggester import ReconAssessment
from tools.memory.attack_store import AttackMemoryItem, AttackMemoryStore
from tools.memory.experience import ExperienceStore
from tools.memory.semantic import SemanticMemoryManager
from tools.memory.session import SessionManager, SessionState, _load_resume_state

if TYPE_CHECKING:
    from tools.providers.embeddings import EmbeddingProvider


# ---------------------------------------------------------------------------
# Facade: one object for the whole memory stack.
# ---------------------------------------------------------------------------


class MemoryService:
    """Single facade over the per-attempt window, cross-mission store,
    checkpoint/resume, and Bayesian confidence.

    Best-effort wiring mirrors the exploit-loop bootstrap
    (``tools/exploit_agent/runner/_impl.py``): sub-stores that cannot be built
    (no DB, no embedding provider) stay ``None`` and their methods return the
    same neutral values the unwired path already produces (``0.5`` / ``[]`` /
    ``None`` / ``""``) instead of raising.
    """

    def __init__(
        self,
        workspace: Path,
        session_id: str = "default",
        target_ip: str = "",
        db: DatabaseManager | None = None,
        *,
        min_samples: int = 3,
        time_decay_days: float = 90.0,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.session_manager = SessionManager(self.workspace)
        self.attack_memory = AttackMemoryStore(self.workspace, session_id, target_ip)
        if db is not None:
            self.experience_store: ExperienceStore | None = ExperienceStore(
                db, min_samples=min_samples, time_decay_days=time_decay_days
            )
        else:
            self.experience_store = None
        if db is not None and embedding_provider is not None:
            self.semantic_memory: SemanticMemoryManager | None = SemanticMemoryManager(
                db, embedding_provider=embedding_provider
            )
        else:
            self.semantic_memory = None

    # ── Checkpoint / resume ───────────────────────────────────────────

    @property
    def session(self) -> SessionState | None:
        """The currently loaded checkpoint state, if any."""
        return self.session_manager._state

    def resume_or_new(self, **kwargs: Any) -> SessionState:
        """Resume the checkpointed session for the target or start a new one."""
        return self.session_manager.resume_or_new(**kwargs)  # type: ignore[arg-type]

    def new_session(self, **kwargs: Any) -> SessionState:
        """Start a fresh checkpointed session."""
        return self.session_manager.new_session(**kwargs)  # type: ignore[arg-type]

    def checkpoint(self) -> None:
        """Flush pending checkpoint state to ``session_state.json``."""
        self.session_manager.save()

    def build_resume_messages(self, system_prompt: str) -> list[dict[str, Any]]:
        """Reconstitute message history for the LLM from saved state."""
        return self.session_manager.build_resume_messages(system_prompt)

    def get_context_summary(self) -> str:
        """Generate a running summary for context compaction."""
        return self.session_manager.get_context_summary()

    def record_action(self, action: str, result: str, success: bool = False) -> None:
        self.session_manager.record_action(action, result, success)

    def record_phase(self, phase: str) -> None:
        self.session_manager.record_phase(phase)

    @staticmethod
    def load_resume_state(reports_dir: Path, args: argparse.Namespace) -> tuple[ReconAssessment, str, str] | None:
        """Reload a saved recon assessment + chosen goal (CLI ``--resume``)."""
        return _load_resume_state(reports_dir, args)

    # ── Per-attempt window ────────────────────────────────────────────

    def capture_tool_result(
        self,
        tool_name: str,
        result_text: str,
        success: bool,
        command: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Extract and persist useful facts from one tool result."""
        return self.attack_memory.capture_tool_result(tool_name, result_text, success, command, metadata)

    def capture_note(
        self,
        category: str,
        key: str,
        value: str,
        *,
        source_tool: str = "",
        success: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Persist one tactical note to the per-attempt window."""
        return self.attack_memory.capture_note(
            category, key, value, source_tool=source_tool, success=success, metadata=metadata
        )

    def format_attack_context(self, max_items: int = 40, max_chars: int = 6000) -> str:
        """Return a compact per-attempt memory block for prompt injection."""
        return self.attack_memory.format_context(max_items, max_chars)

    def list_attack_items(self, category: str | None = None, limit: int = 200) -> list[AttackMemoryItem]:
        """List tactical items in the per-attempt window."""
        return self.attack_memory.list_items(category, limit)

    # ── Cross-mission lessons ─────────────────────────────────────────

    def store_lesson(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> str | None:
        """Store a learned lesson; ``None`` when the semantic store is unwired."""
        if self.semantic_memory is None:
            return None
        return self.semantic_memory.store_lesson(target_signature, action_type, outcome, text, metadata, confidence)

    def find_similar_lessons(
        self,
        text: str,
        action_type: str | None = None,
        outcome: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Find top-k cross-mission lessons; ``[]`` when unwired."""
        if self.semantic_memory is None:
            return []
        return self.semantic_memory.find_similar_lessons(text, action_type, outcome, top_k)

    def find_similar(
        self,
        text: str,
        source_table: str | None = None,
        top_k: int = 5,
        mission_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Find top-k similar embeddings; ``[]`` when unwired."""
        if self.semantic_memory is None:
            return []
        return self.semantic_memory.find_similar(text, source_table, top_k, mission_id)

    # ── Bayesian confidence ───────────────────────────────────────────

    def record_outcome(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        metadata: dict[str, Any] | None = None,
        *,
        action_suffix: str = "",
    ) -> str:
        """Record an outcome observation; ``""`` when the store is unwired."""
        if self.experience_store is None:
            return ""
        return self.experience_store.record_outcome(
            target_signature, action_type, outcome, metadata, action_suffix=action_suffix
        )

    def get_confidence(self, target_signature: str, action_type: str) -> float:
        """Bayesian confidence; neutral ``0.5`` when unwired or thin data."""
        if self.experience_store is None:
            return 0.5
        return self.experience_store.get_confidence(target_signature, action_type)

    def get_best_action(self, target_signature: str, candidates: list[str]) -> tuple[str, float] | None:
        """Highest-confidence candidate; ``None`` when unwired or no candidates."""
        if self.experience_store is None:
            return None
        return self.experience_store.get_best_action(target_signature, candidates)

    def get_all_confidences(self, target_signature: str) -> dict[str, float]:
        """Confidence scores for all known actions; ``{}`` when unwired."""
        if self.experience_store is None:
            return {}
        return self.experience_store.get_all_confidences(target_signature)

    def observation_count(self, target_signature: str, action_type: str) -> int:
        """Decisive-outcome row count; ``0`` when unwired."""
        if self.experience_store is None:
            return 0
        return self.experience_store.observation_count(target_signature, action_type)
