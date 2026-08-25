"""Recon package — canonical location for recon pipeline."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tools.recon.config import HostReconResult, ReconConfig, ServiceInfo, ToolAvailability
    from tools.recon.enumerator import SecondaryEnumerator
    from tools.recon.pipeline import ReconPipeline
    from tools.recon.scanner import PrimaryReconScanner, _kill_process, run_command

__all__ = [
    "HostReconResult",
    "PrimaryReconScanner",
    "ReconConfig",
    "ReconPipeline",
    "SecondaryEnumerator",
    "ServiceInfo",
    "ToolAvailability",
    "_kill_process",
    "run_command",
]

_ATTR_MAP: dict[str, str] = {
    "HostReconResult": "tools.recon.config",
    "ReconConfig": "tools.recon.config",
    "ServiceInfo": "tools.recon.config",
    "ToolAvailability": "tools.recon.config",
    "PrimaryReconScanner": "tools.recon.scanner",
    "_kill_process": "tools.recon.scanner",
    "run_command": "tools.recon.scanner",
    "SecondaryEnumerator": "tools.recon.enumerator",
    "ReconPipeline": "tools.recon.pipeline",
}


def __getattr__(name: str) -> Any:
    if name in _ATTR_MAP:
        mod = importlib.import_module(_ATTR_MAP[name])
        val = getattr(mod, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
