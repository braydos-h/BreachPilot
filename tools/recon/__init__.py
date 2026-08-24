"""Recon package — Phase 4 shim.

Phase 4 splits ``tools/recon_pipeline.py`` (2385 LOC) into ``tools/recon/``
(``scanner.py`` / ``config.py`` / ``pipeline.py`` / ``osint.py``). This
``__init__`` re-exports the public surface so both old and new import paths
work during the 1-release shim window:

  from tools.recon_pipeline import ReconPipeline  # old (still works)
  from tools.recon import ReconPipeline           # new (shim)
  from tools.recon.pipeline import ReconPipeline  # new (shim)

The real split (moving class bodies) lands in the next sub-PR to keep this
diff <400 lines. See ``docs/phase2-audit/architecture-debt.md`` §12.
"""

from tools.recon_pipeline import (  # noqa: F401 -- re-export for shim
    HostReconResult,
    PrimaryReconScanner,
    ReconConfig,
    ReconPipeline,
    SecondaryEnumerator,
    ServiceInfo,
    ToolAvailability,
)

__all__ = [
    "HostReconResult",
    "PrimaryReconScanner",
    "ReconConfig",
    "ReconPipeline",
    "SecondaryEnumerator",
    "ServiceInfo",
    "ToolAvailability",
]
