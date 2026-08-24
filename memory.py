"""Legacy shim -- Flow B frozen. Canonical: legacy.memory. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("memory is legacy; use legacy.memory", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.memory")
sys.modules[__name__] = _mod
