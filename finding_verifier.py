"""Legacy shim -- Flow B frozen. Canonical: legacy.finding_verifier. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("finding_verifier is legacy; use legacy.finding_verifier", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.finding_verifier")
sys.modules[__name__] = _mod
