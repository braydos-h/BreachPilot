"""Legacy shim -- Flow B frozen. Canonical: legacy.report_generator. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn("report_generator is legacy; use legacy.report_generator", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.report_generator")
sys.modules[__name__] = _mod
