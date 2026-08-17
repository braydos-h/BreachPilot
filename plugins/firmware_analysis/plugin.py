"""Firmware analysis plugin (D7).

binwalk/firmadyne/fact-extractor/EMUX for IoT firmware unpack + emulation.
**Local file analysis** → ``@audit_tool`` (no target touch). Emulation is
local (no target touch unless the emulated firmware is treated as a target —
then ``@require_allowlist()`` on the emulated target IP).

The plugin exposes one MCP tool:
- ``unpack_firmware`` — run binwalk to extract a local firmware image. Local
  file analysis → ``@audit_tool``. The firmware path is on the operator box;
  no target IP is involved.

Safety (lab build): plugin is OFF by default. deps: binwalk (the operator
installs it separately; the tool surfaces a clear error if missing).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _binwalk_available() -> bool:
    """True when binwalk is on PATH."""
    return shutil.which("binwalk") is not None


def unpack_firmware_local(firmware_path: str, output_dir: str = "") -> str:
    """Run binwalk to extract a local firmware image. Returns a text summary.

    Local file analysis only — no target IP, no network. Uses subprocess to
    call binwalk (the operator must have it installed). The output goes to a
    ``_firmware_path.extracted`` directory next to the firmware (or
    ``output_dir`` when supplied).
    """
    fw = Path(firmware_path)
    if not fw.exists():
        return f"ERROR: firmware file not found: {firmware_path}"
    if not _binwalk_available():
        return (
            "ERROR: binwalk is not installed. Install it (e.g. `pip install binwalk` "
            "or `apt install binwalk`) to use the firmware analysis plugin."
        )
    out = Path(output_dir) if output_dir else fw.parent / f"{fw.name}.extracted"
    out.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["binwalk", "-e", "-C", str(out), str(fw)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            return f"ERROR: binwalk failed: {proc.stderr[:500]}"
        # List extracted files.
        extracted = []
        if out.exists():
            extracted = sorted(p.name for p in out.rglob("*") if p.is_file())[:50]
        lines = [f"FIRMWARE_UNPACK: {fw.name}", f"output_dir: {out}"]
        if extracted:
            lines.append(f"extracted_files ({len(extracted)}):")
            for name in extracted:
                lines.append(f"  - {name}")
        return "\n".join(lines)
    except subprocess.TimeoutExpired:
        return "ERROR: binwalk timed out (120s)."
    except (FileNotFoundError, OSError) as exc:
        return f"ERROR: binwalk execution failed: {exc}"


class FirmwareAnalysisPlugin(Plugin):
    """Plugin that registers the ``unpack_firmware`` MCP tool."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore
        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        def register_mcp_tools(mcp: Any, ctx: Any) -> None:
            audit_tool = ctx.audit_tool

            @mcp.tool()
            @audit_tool
            def unpack_firmware(firmware_path: str, output_dir: str = "") -> str:
                """Unpack a local firmware image with binwalk.

                Local file analysis only — no target IP, no network. The
                firmware path is on the operator box. ``@audit_tool`` (no
                target touch). If a future variant emulates the firmware and
                treats the emulated host as a target, it MUST switch to
                ``@require_allowlist()`` on the emulated target IP.
                """
                return unpack_firmware_local(firmware_path, output_dir)

        registry.register_mcp_tools(register_mcp_tools)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return FirmwareAnalysisPlugin()
