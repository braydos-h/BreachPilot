"""Legacy shim -- Flow B frozen. Canonical: legacy.task_queue. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("task_queue is legacy; use legacy.task_queue", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.task_queue")
sys.modules[__name__] = _mod
