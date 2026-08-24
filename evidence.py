"""Legacy shim -- Flow B frozen. Canonical: legacy.evidence. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("evidence is legacy; use legacy.evidence", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.evidence")
sys.modules[__name__] = _mod
