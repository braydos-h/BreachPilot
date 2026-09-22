"""Memory package — canonical location for Flow A memory logic.

Split from ``tools.memory_service`` (todo 06) by responsibility:

  - ``helpers`` — truncation / windowing / decay / Beta / cosine.
  - ``attack_store`` — per-attempt tactical facts (AttackMemoryStore).
  - ``experience`` — cross-mission Bayesian confidence (ExperienceStore).
  - ``semantic`` — embedding-based lesson retrieval (SemanticMemoryManager).
  - ``session`` — checkpoint / resume (SessionState, SessionManager).
  - ``service`` — the MemoryService facade.

``tools.memory_service`` is a thin compat shim; the older leaf shims
(``tools.attack_memory``, ``tools.experience_store``,
``tools.semantic_memory``, ``tools.session_manager``,
``tools.resume_state``) keep importing through it.
"""

from __future__ import annotations

from tools.memory.attack_store import ATTACK_MEMORY_DB as ATTACK_MEMORY_DB
from tools.memory.attack_store import AttackMemoryItem as AttackMemoryItem
from tools.memory.attack_store import AttackMemoryStore as AttackMemoryStore
from tools.memory.experience import ExperienceStore as ExperienceStore
from tools.memory.helpers import beta_mean as beta_mean
from tools.memory.helpers import cap_text as cap_text
from tools.memory.helpers import cosine_similarity as cosine_similarity
from tools.memory.helpers import decay_weight as decay_weight
from tools.memory.helpers import one_line as one_line
from tools.memory.helpers import take_last as take_last
from tools.memory.semantic import SemanticMemoryManager as SemanticMemoryManager
from tools.memory.service import MemoryService as MemoryService
from tools.memory.session import SessionManager as SessionManager
from tools.memory.session import SessionState as SessionState
from tools.memory.session import _load_resume_state as _load_resume_state

__all__ = [
    "ATTACK_MEMORY_DB",
    "AttackMemoryItem",
    "AttackMemoryStore",
    "ExperienceStore",
    "MemoryService",
    "SemanticMemoryManager",
    "SessionManager",
    "SessionState",
    "_load_resume_state",
    "beta_mean",
    "cap_text",
    "cosine_similarity",
    "decay_weight",
    "one_line",
    "take_last",
]
