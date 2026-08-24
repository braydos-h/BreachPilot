"""Legacy shim -- Flow B frozen. Canonical: legacy.planner. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("planner is legacy; use legacy.planner", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.planner")
sys.modules[__name__] = _mod
