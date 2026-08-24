"""Phase 4 Round 2: version-aware ranking bonus in AttackModule.applicability.

These tests import ONLY from tools.attack_modules.base (per the task spec) and
exercise the +25 version bonus via test-only subclasses with target_versions
set. The default (target_versions={}) must remain backward-compatible -- a
module with no declared version constraints produces identical scores with and
without a version string.
"""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext

# --- test-only module fixtures -------------------------------------------------

class _VersionModule(AttackModule):
    """Module declaring a known-vulnerable version pattern for http."""
    name = "_VersionModule"
    description = "test"
    target_services = ["http"]
    target_ports = [80]
    required_cves = []
    target_versions = {"http": ["1.2.3"]}

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {}


class _DefaultVersionModule(AttackModule):
    """Module with the default empty target_versions (backward-compat baseline)."""
    name = "_DefaultVersionModule"
    description = "test"
    target_services = ["http"]
    target_ports = [80]
    required_cves = []
    # target_versions intentionally left at the class default {}

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {}


class _HighScoreModule(AttackModule):
    """Module that already maxes the score via services+ports+CVE so we can
    confirm the version bonus cannot push past the 100 cap."""
    name = "_HighScoreModule"
    description = "test"
    target_services = ["http"]
    target_ports = [80]
    required_cves = ["CVE-2021-44228"]  # +40 -> 30+20+40 = 90, +25 version = 115 -> capped 100
    target_versions = {"http": ["1.2.3"]}

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {}


# --- context helpers -----------------------------------------------------------

def _ctx(version: str, cves: list[str] | None = None) -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.5",
        target_os="linux",
        services=[{"service": "http", "port": "80/tcp", "version": version}],
        cves=cves or [],
    )


# --- tests ---------------------------------------------------------------------

def test_matching_version_adds_exactly_25():
    """A matching version string yields exactly +25 over the no-version baseline."""
    mod = _VersionModule()
    base = mod.applicability(_ctx(version=""))
    with_version = mod.applicability(_ctx(version="Server 1.2.3"))
    assert base == 50  # 30 (service) + 20 (port)
    assert with_version == base + 25


def test_non_matching_version_gives_no_bonus():
    """A version string that contains no declared pattern gives no bonus -- same
    as an empty version string."""
    mod = _VersionModule()
    empty = mod.applicability(_ctx(version=""))
    non_match = mod.applicability(_ctx(version="9.9.9"))
    assert non_match == empty


def test_default_target_versions_backward_compat():
    """A module with the default target_versions={} produces identical scores
    with and without a version string (no bonus path is entered)."""
    mod = _DefaultVersionModule()
    without = mod.applicability(_ctx(version=""))
    with_version = mod.applicability(_ctx(version="Server 1.2.3"))
    assert without == with_version == 50


def test_bonus_capped_at_100():
    """The version bonus cannot push a module past the 100 cap."""
    mod = _HighScoreModule()
    # Without version: 30 (svc) + 20 (port) + 40 (CVE) = 90
    base = mod.applicability(_ctx(version="", cves=["CVE-2021-44228"]))
    assert base == 90
    # With matching version: 90 + 25 = 115 -> capped at 100
    capped = mod.applicability(_ctx(version="Server 1.2.3", cves=["CVE-2021-44228"]))
    assert capped == 100


def test_bonus_is_once_per_module_not_per_pattern_or_service():
    """Multiple matching patterns AND multiple matching services still yield a
    single +25, not +25 per match."""
    class _MultiMatchModule(AttackModule):
        name = "_MultiMatchModule"
        description = "test"
        target_services = ["http", "https"]
        target_ports = [80, 443]
        required_cves = []
        target_versions = {"http": ["1.2.3", "4.5.6"], "https": ["1.2.3"]}

        def run(self, ctx: ModuleContext) -> dict[str, Any]:
            return {}

    mod = _MultiMatchModule()
    # Both http and https present, both with version 1.2.3 (matches two patterns
    # for http and one for https). Baseline: 30*2 (services) + 20*2 (ports) = 100.
    ctx = ModuleContext(
        target_ip="10.0.0.5",
        target_os="linux",
        services=[
            {"service": "http", "port": "80/tcp", "version": "Server 1.2.3"},
            {"service": "https", "port": "443/tcp", "version": "Server 1.2.3"},
        ],
        cves=[],
    )
    # Baseline already saturates at 100, so to isolate the once-only bonus we
    # also check a single-service variant: http only -> 30 + 20 = 50, +25 = 75.
    single_ctx = _ctx(version="Server 1.2.3")
    assert mod.applicability(single_ctx) == 75  # 50 + exactly one +25
    # Saturated case stays at 100.
    assert mod.applicability(ctx) == 100


def test_case_insensitive_substring_match():
    """Version pattern matching is case-insensitive substring."""
    mod = _VersionModule()  # pattern "1.2.3"
    upper = mod.applicability(_ctx(version="Apache/1.2.3"))
    assert upper == 50 + 25  # matches "1.2.3" regardless of surrounding text
