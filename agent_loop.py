"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.agent_loop. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "agent_loop is legacy (deprecated since 0.68, remove in 0.71); use legacy.agent_loop",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.agent_loop")
sys.modules[__name__] = _mod
