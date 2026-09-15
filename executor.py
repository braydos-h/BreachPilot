"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.executor. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "executor is legacy (deprecated since 0.68, remove in 0.71); use legacy.executor", DeprecationWarning, stacklevel=2
)
_mod = importlib.import_module("legacy.executor")
sys.modules[__name__] = _mod
