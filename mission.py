"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.mission. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "mission is legacy (deprecated since 0.68, remove in 0.71); use legacy.mission", DeprecationWarning, stacklevel=2
)
_mod = importlib.import_module("legacy.mission")
sys.modules[__name__] = _mod
