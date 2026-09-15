"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.task_queue. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "task_queue is legacy (deprecated since 0.68, remove in 0.71); use legacy.task_queue",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.task_queue")
sys.modules[__name__] = _mod
