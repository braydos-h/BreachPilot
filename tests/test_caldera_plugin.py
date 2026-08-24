"""Tests for the Caldera adversary emulation plugin (D6).

Caldera abilities run against an authorized Caldera server (target-side).
Target-touching tools use ``@require_allowlist()`` — the Caldera server IP
must be in ``exploit.allowed_targets``. Lab build: enabled true.
"""

from __future__ import annotations

from plugins.caldera.plugin import CalderaPlugin, _caldera_config


def test_plugin_factory():
    p = CalderaPlugin()
    assert p.manifest.name == "caldera"
    assert p.manifest.enabled is True  # lab build default


def test_plugin_has_mcp_tool_capability():
    p = CalderaPlugin()
    assert "mcp_tool" in p.manifest.capabilities


def test_register_registers_mcp_tools():
    """register() should call register_mcp_tools on the registry."""
    p = CalderaPlugin()
    recorded = {}

    class _FakeRegistry:
        def register_mcp_tools(self, factory):
            recorded["factory"] = factory

    p.register(_FakeRegistry())
    assert "factory" in recorded


def test_caldera_config_reads_url_and_api_key(monkeypatch):
    """_caldera_config reads url + api_key_env from the caldera config block."""
    monkeypatch.setenv("CALDERA_API_KEY", "secret123")
    url, key = _caldera_config({"caldera": {"url": "https://caldera.local:8888", "api_key_env": "CALDERA_API_KEY"}})
    assert url == "https://caldera.local:8888"
    assert key == "secret123"


def test_caldera_config_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    url, key = _caldera_config({})
    assert url == ""
    assert key == ""


def test_caldera_config_custom_env_var(monkeypatch):
    monkeypatch.setenv("MY_CALDERA_KEY", "custom-key")
    url, key = _caldera_config({"caldera": {"url": "https://c.local", "api_key_env": "MY_CALDERA_KEY"}})
    assert key == "custom-key"


def test_mcp_tools_use_require_allowlist():
    """The plugin's MCP tools must be wrapped with @require_allowlist()."""
    p = CalderaPlugin()
    captured = []

    class _FakeCtx:
        def __init__(self):
            from functools import wraps

            def _require(target_param="target_ip", **kw):
                def deco(fn):
                    @wraps(fn)
                    async def wrapper(*a, **k):
                        return await fn(*a, **k)

                    wrapper.__wrapped_require_allowlist__ = True
                    return wrapper

                return deco

            self.require_allowlist = _require
            self.audit_tool = lambda fn: fn
            self.config = None

    class _FakeMcp:
        def tool(self):
            def deco(fn):
                captured.append(fn)
                return fn

            return deco

    class _FakeRegistry:
        def register_mcp_tools(self, factory):
            factory(_FakeMcp(), _FakeCtx())

    p.register(_FakeRegistry())
    assert len(captured) == 2
    for fn in captured:
        assert getattr(fn, "__wrapped_require_allowlist__", False) is True


def test_caldera_list_abilities_missing_url_error():
    """When caldera.url is unset, the tool surfaces a clear config error."""
    p = CalderaPlugin()
    tool_outputs = []

    class _FakeCtx:
        def __init__(self):
            from functools import wraps

            def _require(*a, **k):
                def deco(fn):
                    @wraps(fn)
                    def wrapper(*args, **kw):
                        return fn(*args, **kw)

                    wrapper.__wrapped_require_allowlist__ = True
                    return wrapper

                return deco

            self.require_allowlist = _require
            self.audit_tool = lambda fn: fn
            self.config = {}  # no caldera block

    class _FakeMcp:
        def tool(self):
            def deco(fn):
                tool_outputs.append(fn)
                return fn

            return deco

    class _FakeRegistry:
        def register_mcp_tools(self, factory):
            factory(_FakeMcp(), _FakeCtx())

    p.register(_FakeRegistry())
    # Call the first tool (caldera_list_abilities) with no config → ERROR.
    result = tool_outputs[0](target_ip="10.0.0.50")
    assert result.startswith("ERROR:")
    assert "caldera.url" in result
