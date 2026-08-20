"""Attempt fingerprinting + retry-justification primitives.

Pure logic, stdlib only, no IO. See `attempt.py` (fingerprint inputs and
retry justification) and `tracker.py` (in-memory attempt store).
"""

from .attempt import (
    ActionFamily,
    Attempt,
    AttemptStatus,
    RetryJustification,
    RetryJustifier,
    mask_secrets,
)
from .tracker import (
    PERMANENT_FAILURE_MARKERS,
    AttemptTracker,
    is_permanent_failure,
)

__all__ = [
    "ActionFamily",
    "Attempt",
    "AttemptStatus",
    "AttemptTracker",
    "PERMANENT_FAILURE_MARKERS",
    "RetryJustification",
    "RetryJustifier",
    "is_permanent_failure",
    "mask_secrets",
]
