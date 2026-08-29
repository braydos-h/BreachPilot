"""XbenProvider: the XBEN benchmark suite provider.

Discovers ``benchmarks/xben/*.json`` manifests (one challenge per file, or a
top-level list) and adapts them into standard BenchmarkScenario objects via
:mod:`tools.benchmark.xben.manifest`. The manifest directory is injectable so
tests register scenarios without touching the repo's ``benchmarks/`` tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.benchmark.models import BenchmarkScenario
from tools.benchmark.registry import BenchmarkProvider, default_manifest_dir
from tools.benchmark.xben.manifest import ManifestError, load_manifest_file

__all__ = ["XbenProvider"]


class XbenProvider(BenchmarkProvider):
    """Loads XBEN-style challenge manifests as benchmark scenarios."""

    suite_id = "xben"

    def __init__(self, manifest_dir: Path | str | None = None) -> None:
        self.manifest_dir = Path(manifest_dir) if manifest_dir else default_manifest_dir("xben")

    def _manifest_paths(self) -> list[Path]:
        if not self.manifest_dir.exists():
            return []
        return sorted(p for p in self.manifest_dir.glob("*.json") if p.is_file())

    def load_scenarios(
        self,
        *,
        scenario_ids: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[BenchmarkScenario]:
        scenarios: list[BenchmarkScenario] = []
        for path in self._manifest_paths():
            try:
                scenarios.extend(load_manifest_file(path, suite=self.suite_id))
            except ManifestError:
                continue  # an invalid manifest never aborts the suite; report via describe()
        wanted_ids = {str(s) for s in (scenario_ids or [])}
        wanted_tags = {str(t).lower() for t in (tags or [])}
        out: list[BenchmarkScenario] = []
        for scenario in scenarios:
            if wanted_ids and scenario.scenario_id not in wanted_ids:
                continue
            if wanted_tags and not wanted_tags.intersection({t.lower() for t in scenario.tags}):
                continue
            out.append(scenario)
        return out

    def describe(self) -> dict[str, Any]:
        scenarios = self.load_scenarios()
        invalid = 0
        for path in self._manifest_paths():
            try:
                load_manifest_file(path, suite=self.suite_id)
            except ManifestError:
                invalid += 1
        tags: dict[str, int] = {}
        for s in scenarios:
            for t in s.tags:
                tags[t] = tags.get(t, 0) + 1
        return {
            "suite_id": self.suite_id,
            "scenarios": len(scenarios),
            "invalid_manifests": invalid,
            "manifest_dir": str(self.manifest_dir),
            "tags": dict(sorted(tags.items())),
        }
