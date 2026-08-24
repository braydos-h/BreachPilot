"""Legacy shim -- Flow B frozen. Canonical: legacy.executor. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("executor is legacy; use legacy.executor", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.executor")
sys.modules[__name__] = _mod
