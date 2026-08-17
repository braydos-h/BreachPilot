"""Tests for the firmware analysis plugin (D7).

Local firmware unpack with binwalk → ``@audit_tool`` (no target touch).
Plugin is default-off. The tool surfaces a clear error when binwalk is missing.
"""

from __future__ import annotations

from pathlib import Path

from plugins.firmware_analysis.plugin import (
    FirmwareAnalysisPlugin,
    unpack_firmware_local,
)


def test_plugin_factory():
    p = FirmwareAnalysisPlugin()
    assert p.manifest.name == "firmware_analysis"
    assert p.manifest.enabled is True  # lab build default


def test_plugin_has_mcp_tool_capability():
    p = FirmwareAnalysisPlugin()
    assert "mcp_tool" in p.manifest.capabilities


def test_unpack_missing_firmware_returns_error(tmp_path):
    """A missing firmware file → ERROR result (no subprocess call)."""
    result = unpack_firmware_local(str(tmp_path / "nope.bin"))
    assert result.startswith("ERROR:")
    assert "not found" in result.lower()


def test_unpack_missing_binwalk_returns_error(tmp_path, monkeypatch):
    """When binwalk is not installed, the tool surfaces a clear install hint."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 64)
    monkeypatch.setattr("plugins.firmware_analysis.plugin._binwalk_available", lambda: False)
    result = unpack_firmware_local(str(fw))
    assert result.startswith("ERROR:")
    assert "binwalk" in result.lower()
    assert "install" in result.lower()


def test_unpack_calls_binwalk_when_available(tmp_path, monkeypatch):
    """When binwalk is available, the tool calls it via subprocess."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 64)
    monkeypatch.setattr("plugins.firmware_analysis.plugin._binwalk_available", lambda: True)

    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        # Return a successful result with a fake extracted file.
        out_dir = Path(cmd[cmd.index("-C") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "squashfs-root").mkdir(exist_ok=True)
        (out_dir / "squashfs-root" / "bin").write_bytes(b"\x00")
        class _Proc:
            returncode = 0
            stdout = "DECIMAL       HEX         DESCRIPTION\n0             0x0         SquashFS"
            stderr = ""
        return _Proc()

    monkeypatch.setattr("plugins.firmware_analysis.plugin.subprocess.run", _fake_run)
    result = unpack_firmware_local(str(fw))
    assert "FIRMWARE_UNPACK:" in result
    assert "fw.bin" in result
    assert "extracted_files" in result
    assert "squashfs-root" in result or "bin" in result
    # Verify binwalk was called with -e -C <out_dir> <firmware>.
    assert "binwalk" in captured["cmd"]
    assert "-e" in captured["cmd"]
    assert "-C" in captured["cmd"]


def test_mcp_tool_is_audit_tool():
    """The plugin's MCP tool is @audit_tool-decorated (local, no target)."""
    p = FirmwareAnalysisPlugin()
    captured = []

    class _FakeCtx:
        def __init__(self):
            def _audit(fn):
                fn.__wrapped_audit_tool__ = True
                return fn
            self.audit_tool = _audit
            from functools import wraps
            def _require(*a, **k):
                def deco(fn):
                    @wraps(fn)
                    async def wrapper(*args, **kw):
                        return await fn(*args, **kw)
                    wrapper.__wrapped_require_allowlist__ = True
                    return wrapper
                return deco
            self.require_allowlist = _require

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
    assert len(captured) == 1
    assert getattr(captured[0], "__wrapped_audit_tool__", False) is True
    # Must NOT be wrapped with @require_allowlist (local-only, no target).
    assert not getattr(captured[0], "__wrapped_require_allowlist__", False)
