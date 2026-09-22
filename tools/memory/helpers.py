"""Memory helpers: truncation, windowing, decay, Beta posterior, cosine (split from tools.memory_service)."""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    import numpy as _np

_logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Shared helpers (deduplicated windowing / truncation / decay logic)
# ---------------------------------------------------------------------------


def cap_text(text: str, max_chars: int) -> str:
    """Truncate ``text`` to ``max_chars`` with a ``...`` suffix on overflow."""
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def one_line(text: str, max_chars: int = 500) -> str:
    """Collapse ``text`` to a single line capped at ``max_chars``."""
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    return cap_text(clean, max_chars)


def take_last(items: Sequence[T], limit: int) -> list[T]:
    """Return the last ``limit`` items as a list (bounded-window helper).

    Behavior-identical to the ``items[-limit:]`` slices previously scattered
    across the session/checkpoint code; ``limit <= 0`` yields ``[]``.
    """
    if limit <= 0:
        return []
    return list(items[-limit:])


def decay_weight(created_at: str, half_life_days: float) -> float:
    """Exponential decay weight in [0, 1] for a row's ``created_at``.

    1.0 at age 0, 0.5 at age ``half_life_days``, decaying toward 0. Returns
    1.0 (no decay) when ``half_life_days`` <= 0 or the timestamp is
    unparseable — never raises on a bad row.
    """
    if half_life_days <= 0.0:
        return 1.0
    try:
        created = datetime.fromisoformat(created_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(
            0.0,
            (datetime.now(timezone.utc) - created).total_seconds() / 86400.0,
        )
        return float(math.exp(-age_days / half_life_days))
    except Exception:
        return 1.0


def beta_mean(successes: float, failures: float, partials: float = 0.0) -> float:
    """Mean of the Beta(1+s+p, 1+f+p) posterior for outcome weights."""
    alpha = 1.0 + successes + partials
    beta = 1.0 + failures + partials
    return alpha / (alpha + beta)


def cosine_similarity(a: _np.ndarray, b: _np.ndarray) -> float:
    """Cosine similarity with defensive 0.0 guards.

    Shape mismatch (different embedding dimensions across rows), non-finite
    (NaN/inf) inputs, and a non-finite result all return 0.0 — the neutral
    "no information" score callers already treat as a non-match.
    """
    import numpy as np  # ponytail: lazy — paid only when recall actually runs

    if a.shape != b.shape:
        return 0.0
    if not (np.isfinite(a).all() and np.isfinite(b).all()):
        return 0.0
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    sim = float(np.dot(a, b) / (norm_a * norm_b))
    if not np.isfinite(sim):
        return 0.0
    return sim
