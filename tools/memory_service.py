"""Thin compat shim — implementation lives in :mod:`tools.memory`.

Split by responsibility (todo 06): ``tools/memory/helpers.py``,
``attack_store.py``, ``experience.py``, ``semantic.py``, ``session.py``,
``service.py``. Older leaf shims (``tools.attack_memory`` etc.) keep
importing through this module.
"""

from __future__ import annotations

from tools.memory import (
    ATTACK_MEMORY_DB as ATTACK_MEMORY_DB,
)
from tools.memory import (
    AttackMemoryItem as AttackMemoryItem,
)
from tools.memory import (
    AttackMemoryStore as AttackMemoryStore,
)
from tools.memory import (
    ExperienceStore as ExperienceStore,
)
from tools.memory import (
    MemoryService as MemoryService,
)
from tools.memory import (
    SemanticMemoryManager as SemanticMemoryManager,
)
from tools.memory import (
    SessionManager as SessionManager,
)
from tools.memory import (
    SessionState as SessionState,
)
from tools.memory import (
    _load_resume_state as _load_resume_state,
)
from tools.memory import (
    beta_mean as beta_mean,
)
from tools.memory import (
    cap_text as cap_text,
)
from tools.memory import (
    cosine_similarity as cosine_similarity,
)
from tools.memory import (
    decay_weight as decay_weight,
)
from tools.memory import (
    one_line as one_line,
)
from tools.memory import (
    take_last as take_last,
)

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
