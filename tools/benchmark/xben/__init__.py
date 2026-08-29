"""XBEN benchmark package.

XBEN-style challenge manifests (``benchmarks/xben/*.json``) are adapted into
standard :class:`tools.benchmark.models.BenchmarkScenario` objects — XBEN is
one provider among future suites, never a hard-coded engine path.
"""

from __future__ import annotations

__all__ = ["XbenProvider", "parse_manifest"]

from tools.benchmark.xben.adapter import XbenProvider
from tools.benchmark.xben.manifest import parse_manifest
