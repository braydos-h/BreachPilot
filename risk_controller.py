"""Legacy shim -- Flow B frozen. Canonical: legacy.risk_controller. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("risk_controller is legacy; use legacy.risk_controller", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.risk_controller")
sys.modules[__name__] = _mod
