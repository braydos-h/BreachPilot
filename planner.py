"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.planner. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "planner is legacy (deprecated since 0.68, remove in 0.71); use legacy.planner", DeprecationWarning, stacklevel=2
)
_mod = importlib.import_module("legacy.planner")
sys.modules[__name__] = _mod
