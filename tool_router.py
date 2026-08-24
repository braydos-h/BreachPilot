"""Legacy shim -- Flow B frozen. Canonical: legacy.tool_router. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("tool_router is legacy; use legacy.tool_router", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.tool_router")
sys.modules[__name__] = _mod
