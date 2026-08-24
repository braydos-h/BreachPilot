"""Legacy shim -- Flow B frozen. Canonical: legacy.agent_loop. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("agent_loop is legacy; use legacy.agent_loop", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.agent_loop")
sys.modules[__name__] = _mod
