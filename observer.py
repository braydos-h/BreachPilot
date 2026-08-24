"""Legacy shim -- Flow B frozen. Canonical: legacy.observer. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("observer is legacy; use legacy.observer", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.observer")
sys.modules[__name__] = _mod
