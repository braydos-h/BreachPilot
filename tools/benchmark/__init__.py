"""BreachPilot Benchmark Suite.

First-class, reproducible benchmarking on the existing evaluation
infrastructure: providers (XBEN is one) -> scenario definitions -> sandboxed
agent execution -> independent oracle verification -> metrics -> persistence
-> WebUI/API presentation.

Ground truth is ALWAYS the independent verifier
(:mod:`tools.benchmark.verifier` reusing :mod:`tools.eval_checks`); the
agent's claimed success is stored separately for false-positive detection.
See ``docs/benchmarks.md``.
"""

from __future__ import annotations

__all__ = [
    "BenchmarkScenario",
    "TrialResult",
    "RunConfig",
    "RunSummary",
    "TrialStatus",
    "FailureCategory",
    "BenchmarkRunner",
    "BenchmarkStorage",
    "BenchmarkService",
    "IndependentVerifier",
    "TargetManager",
    "register_provider",
    "get_provider",
    "list_suites",
    "register_default_providers",
    "seed_fake_suite",
]

from tools.benchmark.models import (
    BenchmarkScenario,
    FailureCategory,
    RunConfig,
    RunSummary,
    TrialResult,
    TrialStatus,
)
from tools.benchmark.registry import get_provider, list_suites, register_provider
from tools.benchmark.runner import BenchmarkRunner
from tools.benchmark.service import BenchmarkService
from tools.benchmark.storage import BenchmarkStorage
from tools.benchmark.targets import TargetManager
from tools.benchmark.verifier import IndependentVerifier


def register_default_providers() -> None:
    """Register the built-in suite providers (idempotent)."""
    from tools.benchmark.xben.adapter import XbenProvider

    register_provider(XbenProvider())


def seed_fake_suite(scenarios: list["BenchmarkScenario"]) -> None:
    """Register an in-memory deterministic suite (tests / CI smoke runs).

    The fake provider returns exactly the scenarios it is given — no docker,
    no model, no network. Used by the CI benchmark smoke test.
    """

    class _FakeProvider:
        suite_id = scenarios[0].suite if scenarios else "fake"

        def load_scenarios(self, *, scenario_ids=None, tags=None):  # type: ignore[no-untyped-def]
            wanted_ids = {str(s) for s in (scenario_ids or [])}
            wanted_tags = {str(t).lower() for t in (tags or [])}
            out = []
            for s in scenarios:
                if wanted_ids and s.scenario_id not in wanted_ids:
                    continue
                if wanted_tags and not wanted_tags.intersection({t.lower() for t in s.tags}):
                    continue
                out.append(s)
            return out

        def describe(self):  # type: ignore[no-untyped-def]
            return {"suite_id": self.suite_id, "scenarios": len(scenarios)}

    register_provider(_FakeProvider())  # type: ignore[arg-type]
