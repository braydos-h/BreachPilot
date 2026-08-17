"""Mobile attack plugin for NetAttackAi.

Wraps frida/objection/apktool/jadx for mobile testing. Local APK analysis uses
``@audit_tool`` (no target touch); device-touching tools (USB / remote frida
server) use ``@require_allowlist()`` with the device IP/host as the target.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Local APK analysis (decompile, inspect) uses ``@audit_tool`` (audit trail
  only, no target touch — the APK is a file on the operator box).
* Device-touching tools (attach to a remote frida server, instrument a live
  app) use ``@require_allowlist()`` with the device IP/host as the target.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.mobile_attack")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _mobile_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("mobile_attack") or {}
    return cfg_block if isinstance(cfg_block, dict) else {}


def _run_tool(binary: str, argv: list[str], timeout: int = 60) -> tuple[str, int | None, str]:
    """Invoke an external mobile-tooling binary with argv-list (no shell)."""
    cmd = [binary] + argv
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout, proc.returncode, proc.stderr
    except subprocess.TimeoutExpired:
        return "", None, f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return "", None, f"{binary} not found on PATH"
    except Exception as exc:  # noqa: BLE001
        return "", None, f"{binary} error: {exc}"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class MobileAttackPlugin(Plugin):
    """Plugin wrapper that registers the mobile-attack MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_mobile_tools)


def _register_mobile_tools(mcp: Any, ctx: Any) -> None:
    """Register mobile-attack MCP tools. Local APK analysis uses @audit_tool;
    device-touching tools use @require_allowlist()."""
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    config = ctx.config

    # --- Local APK analysis (audit-only, no target touch) ---------------------

    @mcp.tool()
    @audit_tool
    def mobile_apk_decompile(apk_path: str, decompiler: str = "apktool") -> str:
        """Decompile an APK with apktool or jadx for local static analysis.

        LOCAL-ONLY: the APK is a file on the operator box. This tool never
        touches a target; it uses ``@audit_tool`` for the audit trail only.
        """
        if not apk_path or not apk_path.strip():
            return "BLOCKED: apk_path is required."
        cfg = _mobile_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: mobile_attack plugin not enabled in config."

        candidate = Path(apk_path)
        if not candidate.is_absolute():
            candidate = workspace / apk_path
        if not candidate.exists() or not candidate.is_file():
            return f"BLOCKED: APK not found: {candidate}"

        if decompiler == "jadx":
            binary = shutil.which(str(cfg.get("jadx_path", "jadx"))) or "jadx"
            out_dir = candidate.parent / (candidate.stem + "_jadx")
            argv = ["-d", str(out_dir), str(candidate)]
        else:
            binary = shutil.which(str(cfg.get("apktool_path", "apktool"))) or "apktool"
            out_dir = candidate.parent / (candidate.stem + "_apktool")
            argv = ["d", "-f", "-o", str(out_dir), str(candidate)]

        out, rc, err = _run_tool(binary, argv, timeout=120)
        if rc is None or rc != 0:
            return f"MOBILE_DECOMPILE_ERROR: {err or out}"
        return (
            f"MOBILE_DECOMPILE_RESULT: success\n"
            f"APK: {candidate}\n"
            f"OUT: {out_dir}\n"
            f"DECOMPILER: {decompiler}\n"
            f"OUTPUT: {out[:2000]}"
        )

    @mcp.tool()
    @audit_tool
    def mobile_apk_inspect(apk_path: str) -> str:
        """Inspect a decompiled APK directory for common mobile-app issues:
        hardcoded secrets, insecure HTTP endpoints, exported components,
        weak crypto. LOCAL-ONLY; uses ``@audit_tool``.
        """
        if not apk_path or not apk_path.strip():
            return "BLOCKED: apk_path is required."
        cfg = _mobile_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: mobile_attack plugin not enabled in config."

        # Accept either the APK path (decompile on the fly) or the decompiled
        # directory. For simplicity, this tool reads common files under the
        # decompiled tree.
        candidate = Path(apk_path)
        if not candidate.is_absolute():
            candidate = workspace / apk_path
        if not candidate.exists():
            return f"BLOCKED: path not found: {candidate}"

        # ponytail: a small static-grep over the decompiled tree. Ceiling:
        # does not follow obfuscated string constants; upgrade path is a
        # dedicated mobile SAST (MobSF) integration when this grep is insufficient.
        findings: list[str] = []
        if candidate.is_file() and candidate.suffix == ".apk":
            findings.append("APK file given; run mobile_apk_decompile first to inspect contents.")
        else:
            patterns = [
                (r"http://[a-zA-Z0-9.-]+", "insecure_http_endpoint"),
                (r"(?i)(password|secret|api[_-]?key|token)\s*[=:]\s*[\"'][^\"']+[\"']", "hardcoded_secret"),
            ]
            import re

            for path in candidate.rglob("*"):
                if not path.is_file() or path.suffix.lower() in (".png", ".jpg", ".so", ".dex"):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    continue
                for rx, label in patterns:
                    for m in re.finditer(rx, text):
                        findings.append(f"{label}: {path.name}: {m.group(0)[:120]}")

        if not findings:
            return f"MOBILE_INSPECT_RESULT: no findings in {candidate}"
        return (
            f"MOBILE_INSPECT_RESULT: {len(findings)} finding(s)\n"
            f"PATH: {candidate}\n"
            + "\n".join(findings[:100])
        )

    # --- Device-touching tools (allowlist-gated) -----------------------------

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def mobile_frida_attach(target_ip: str, app_id: str, script_path: str = "") -> str:
        """Attach a Frida script to a running app on a remote device.

        The device IP/host MUST be in exploit.allowed_targets (exact host:port,
        never a wildcard). The frida-server must already be running on the
        device. The script_path (if given) is a Frida JS file on the operator
        box; if empty, a default enumerate-modules script is used.
        """
        if not app_id or not app_id.strip():
            return "BLOCKED: app_id is required."
        cfg = _mobile_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: mobile_attack plugin not enabled in config."

        host = f"{target_ip}:{int(cfg.get('frida_server_port', 27042))}"
        frida_bin = shutil.which("frida") or "frida"
        script_arg = []
        if script_path:
            sp = Path(script_path)
            if not sp.is_absolute():
                sp = workspace / script_path
            if not sp.exists():
                return f"BLOCKED: script not found: {sp}"
            script_arg = ["-l", str(sp)]

        argv = ["-H", host, app_id] + script_arg
        out, rc, err = _run_tool(frida_bin, argv, timeout=60)
        if rc is None or rc != 0:
            return f"MOBILE_FRIDA_ATTACH_ERROR: {err or out}"
        return (
            f"MOBILE_FRIDA_ATTACH_RESULT: success\n"
            f"DEVICE: {target_ip}\n"
            f"APP: {app_id}\n"
            f"OUTPUT: {out[:4000]}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def mobile_frida_list_apps(target_ip: str) -> str:
        """List running apps on a remote device via frida-ps.

        The device IP/host MUST be in exploit.allowed_targets. Uses the
        frida-ps CLI; the frida-server must already be running on the device.
        """
        cfg = _mobile_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: mobile_attack plugin not enabled in config."
        host = f"{target_ip}:{int(cfg.get('frida_server_port', 27042))}"
        ps_bin = shutil.which("frida-ps") or "frida-ps"
        argv = ["-H", host]
        out, rc, err = _run_tool(ps_bin, argv, timeout=30)
        if rc is None or rc != 0:
            return f"MOBILE_FRIDA_LIST_APPS_ERROR: {err or out}"
        return (
            f"MOBILE_FRIDA_LIST_APPS_RESULT: success\n"
            f"DEVICE: {target_ip}\n"
            f"APPS:\n{out[:4000]}"
        )


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return MobileAttackPlugin()
