"""Legacy shim -- Flow B frozen. Deprecated since 0.68, remove in 0.71. Canonical: legacy.finding_verifier. See legacy/README.md."""

import importlib
import sys
import warnings

warnings.warn(
    "finding_verifier is legacy (deprecated since 0.68, remove in 0.71); use legacy.finding_verifier",
    DeprecationWarning,
    stacklevel=2,
)
_mod = importlib.import_module("legacy.finding_verifier")
sys.modules[__name__] = _mod
