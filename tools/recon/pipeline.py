"""Recon pipeline orchestrator — Phase 4 shim.

Real implementation still lives in ``tools.recon_pipeline.ReconPipeline``
(2385 LOC). This module re-exports it so the new path works; the body will
move here in the next sub-PR (``tools/recon/pipeline.py`` 100 lines as per
spec). See ``docs/phase2-audit/architecture-debt.md`` §12.
"""

from tools.recon_pipeline import ReconPipeline  # noqa: F401

__all__ = ["ReconPipeline"]
