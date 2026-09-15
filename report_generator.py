"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.report_generator. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "report_generator is legacy (deprecated since 0.68, remove in 0.71); use legacy.report_generator",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.report_generator")
sys.modules[__name__] = _mod
