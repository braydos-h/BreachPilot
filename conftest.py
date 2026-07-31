"""Pytest conftest: shared fixtures and test-isolation guards.

Two concerns live here:

1. pytest 9.0.3 ``PosixPath`` INTERNALERROR workaround on Windows (a monkeypatch
   of ``_pytest.nodes.Node._repr_failure_py`` that falls back to a plain
   traceback when the stock repr raises ``NotImplementedError``).

2. An autouse fixture that snapshots + restores the four ``EXPLOIT_*`` env vars
   that production code mutates via raw ``os.environ[...] = ...`` (not via
   monkeypatch). ``tools/mcp_shared.add_discovered_target`` writes
   ``EXPLOIT_DISCOVERED_TARGETS`` directly, and ``tools/mcp_session`` sets
   ``EXPLOIT_TARGET`` / ``EXPLOIT_TARGET_IP`` / ``EXPLOIT_TARGET_DOMAIN`` on the
   server subprocess env. Tests that exercise these paths leak the values into
   later tests because ``monkeypatch.delenv(k, raising=False)`` on an already-
   unset key records nothing, so a subsequent raw write is not reverted on
   teardown. The leaking values pollute the allowlist union
   (``_allowed_target_list``) and break the empty-allowlist / invalid-target /
   ollama-unreachable tests non-deterministically. Snapshot+restore around every
   test is the standard fix for process-global env written outside monkeypatch.
"""
import os
import traceback

import pytest

try:
    import _pytest.nodes as _n

    _orig = _n.Node._repr_failure_py

    def _safe(self, excinfo, *a, **k):
        try:
            return _orig(self, excinfo, *a, **k)
        except NotImplementedError:
            return "".join(traceback.format_exception(excinfo.type, excinfo.value, excinfo.tb))

    _n.Node._repr_failure_py = _safe
except Exception:
    pass


# Env vars that production code writes via raw os.environ (not monkeypatch) and
# that feed the allowlist union in tools.mcp_shared._allowed_target_list. Tests
# that trigger add_discovered_target / run_autonomous_campaign leak these into
# later tests; snapshot+restore keeps each test hermetic.
_EXPLOIT_ENV_VARS = (
    "EXPLOIT_TARGET",
    "EXPLOIT_TARGET_IP",
    "EXPLOIT_TARGET_DOMAIN",
    "EXPLOIT_DISCOVERED_TARGETS",
)


@pytest.fixture(autouse=True)
def _isolate_exploit_target_env():
    """Snapshot + restore the EXPLOIT_* env vars around every test.

    Restores both the value AND the presence/absence of each key, so a test that
    writes ``os.environ["EXPLOIT_DISCOVERED_TARGETS"] = "..."`` directly cannot
    leak it into a later test (which broke the empty-allowlist tests, the
    invalid-target rejection tests, and the ollama-unreachable fallback test).
    """
    snapshot = {k: os.environ.get(k) for k in _EXPLOIT_ENV_VARS}
    yield
    for k in _EXPLOIT_ENV_VARS:
        original = snapshot[k]
        if original is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = original