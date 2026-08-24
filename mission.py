"""Legacy shim -- Flow B frozen. Canonical: legacy.mission. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("mission is legacy; use legacy.mission", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.mission")
sys.modules[__name__] = _mod
