"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.evidence. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "evidence is legacy (deprecated since 0.68, remove in 0.71); use legacy.evidence", DeprecationWarning, stacklevel=2
)
_mod = importlib.import_module("legacy.evidence")
sys.modules[__name__] = _mod
