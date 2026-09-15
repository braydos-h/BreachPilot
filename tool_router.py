"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.tool_router. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "tool_router is legacy (deprecated since 0.68, remove in 0.71); use legacy.tool_router",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.tool_router")
sys.modules[__name__] = _mod
