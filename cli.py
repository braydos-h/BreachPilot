"""Legacy shim -- Flow B frozen. Canonical: legacy.cli. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("cli is legacy; use legacy.cli", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.cli")
sys.modules[__name__] = _mod
