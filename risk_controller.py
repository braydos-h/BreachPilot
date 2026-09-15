"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.risk_controller. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "risk_controller is legacy (deprecated since 0.68, remove in 0.71); use legacy.risk_controller",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.risk_controller")
sys.modules[__name__] = _mod
