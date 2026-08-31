"""Browser capability metadata tests (architecture-only build).

Pins the capability vocabulary and its availability rule: every declared
``browser.*`` capability reports ``available: False`` on a stock install, and
nothing but a registered, configured backend can ever flip that — declared is
NEVER available.
"""

from __future__ import annotations

import pytest

from tools.browser.capabilities import (
    BACKEND_REGISTRY,
    BROWSER_CAPABILITIES,
    backend_configured,
    browser_available,
    browser_capabilities,
    browser_capability_names,
    unmet_requirements,
)

EXPECTED_CAPABILITIES = (
    "browser.navigate",
    "browser.dom.inspect",
    "browser.javascript.execute",
    "browser.network.observe",
    "browser.network.replay",
    "browser.storage.read",
    "browser.form.inspect",
    "browser.form.submit",
    "browser.screenshot",
    "browser.endpoint.discover",
)


def test_capability_vocabulary_is_stable():
    assert tuple(browser_capability_names()) == EXPECTED_CAPABILITIES
    assert set(BROWSER_CAPABILITIES) == set(EXPECTED_CAPABILITIES)


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        {"browser": {}},
        {"browser": {"enabled": False, "backend": "playwright"}},
        {"browser": {"enabled": True, "backend": "none"}},
        {"browser": {"enabled": True, "backend": "playwright"}},  # declared ≠ available
    ],
)
def test_all_capabilities_report_unavailable_on_stock_builds(config):
    records = browser_capabilities(config)
    assert {r["name"] for r in records} == set(EXPECTED_CAPABILITIES)
    assert all(r["available"] is False for r in records)
    assert browser_available(config) is False


def test_backend_configured_requires_a_registered_entry():
    """A configured-but-never-registered backend name fails closed."""
    assert backend_configured("none") is False
    assert backend_configured("playwright") is False
    assert backend_configured("") is False


def test_record_shape_is_metadata_only():
    record = browser_capabilities({})[0]
    assert set(record) == {"name", "description", "read_only", "available"}
    # read_only flags: mutating operations are flagged non-read-only for planner costing.
    read_only = {r["name"] for r in browser_capabilities({}) if r["read_only"]}
    assert "browser.dom.inspect" in read_only
    assert "browser.navigate" not in read_only
    assert "browser.javascript.execute" not in read_only
    assert "browser.form.submit" not in read_only


def test_unmet_requirements_when_nothing_is_available():
    cfg = {"browser": {"enabled": True, "backend": "none"}}
    assert unmet_requirements(["browser.navigate", "browser.dom.inspect"], cfg) == [
        "browser.navigate",
        "browser.dom.inspect",
    ]


def test_unmet_requirements_empty_when_nothing_required():
    cfg = {"browser": {"enabled": False}}
    assert unmet_requirements([], cfg) == []
    assert unmet_requirements(None, cfg) == []


def test_unknown_capability_names_are_always_unmet():
    """Nothing provides them — not even a hypothetical fully-configured backend."""
    assert "browser.teleport" in unmet_requirements(["browser.teleport"])


def test_registry_has_no_builtin_backends():
    """Only future backend modules register here — the ONLY route to available."""
    assert BACKEND_REGISTRY == {}
