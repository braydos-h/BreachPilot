"""Wireless / Bluetooth assessment plugin for BreachPilot.

Wraps bettercap / aircrack-ng / hcxtools / bluez for authorized WLAN/BT
assessments. Radio-touching tools use ``@require_allowlist()`` with the BSSID
(or the BT device address) treated as the target identifier.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Radio-touching tools (deauth, channel hop, PMKID capture) use
  ``@require_allowlist()`` with the BSSID as the target_ip argument — the
  operator MUST add the BSSID to ``exploit.allowed_targets`` explicitly
  (exact BSSID, never a wildcard).
* No log clearing, timestomping, EDR/AV defeat, DoS against unauthorized
  networks, or malware distribution. Deauth against the operator's own / a
  contracted network only.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.wireless")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _wireless_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("wireless") or {}
    return cfg_block if isinstance(cfg_block, dict) else {}


def _run_tool(binary: str, argv: list[str], timeout: int = 60) -> tuple[str, int | None, str]:
    """Invoke an external wireless-tooling binary with argv-list (no shell)."""
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


class WirelessPlugin(Plugin):
    """Plugin wrapper that registers the wireless-assessment MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_wireless_tools)


def _register_wireless_tools(mcp: Any, ctx: Any) -> None:
    """Register wireless-assessment MCP tools. Radio-touching tools use
    ``@require_allowlist()`` with the BSSID as the target_ip argument."""
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def wireless_recon(target_ip: str, interface: str = "") -> str:
        """Run a passive wireless recon sweep on the configured interface.

        ``target_ip`` here is treated as the BSSID of the network to focus on.
        Uses bettercap's ``wifi.recon on`` + ``wifi.show`` to enumerate nearby
        APs and clients. The BSSID must be in exploit.allowed_targets.
        """
        cfg = _wireless_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: wireless plugin not enabled in config."
        iface = interface or str(cfg.get("interface", "wlan0mon"))
        binary = shutil.which(str(cfg.get("bettercap_path", "bettercap"))) or "bettercap"
        argv = [
            "-iface",
            iface,
            "-eval",
            f"wifi.recon on; sleep {int(cfg.get('channel_timeout_seconds', 30))}; wifi.show",
        ]
        out, rc, err = _run_tool(binary, argv, timeout=int(cfg.get("channel_timeout_seconds", 30)) + 30)
        if rc is None or rc != 0:
            return f"WIRELESS_RECON_ERROR: {err or out}"
        return f"WIRELESS_RECON_RESULT: success\nBSSID_FOCUS: {target_ip}\nINTERFACE: {iface}\nOUTPUT:\n{out[:4000]}"

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def wireless_deauth(target_ip: str, client_mac: str = "", interface: str = "") -> str:
        """Send deauth frames to a target BSSID (and optionally a single client).

        DANGEROUS: only against networks you own or are explicitly contracted
        to test. ``target_ip`` is the BSSID; it MUST be in
        exploit.allowed_targets. Uses bettercap's ``wifi.deauth``.
        """
        cfg = _wireless_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: wireless plugin not enabled in config."
        iface = interface or str(cfg.get("interface", "wlan0mon"))
        binary = shutil.which(str(cfg.get("bettercap_path", "bettercap"))) or "bettercap"
        eval_cmd = f"wifi.deauth {target_ip}"
        if client_mac:
            eval_cmd += f" --client {client_mac}"
        argv = ["-iface", iface, "-eval", eval_cmd]
        out, rc, err = _run_tool(binary, argv, timeout=30)
        if rc is None or rc != 0:
            return f"WIRELESS_DEAUTH_ERROR: {err or out}"
        return (
            f"WIRELESS_DEAUTH_RESULT: sent\n"
            f"BSSID: {target_ip}\n"
            f"CLIENT: {client_mac or '(broadcast)'}\n"
            f"OUTPUT:\n{out[:2000]}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def wireless_pmkid_capture(target_ip: str, interface: str = "") -> str:
        """Capture PMKID frames from a target BSSID using hcxdumptool.

        ``target_ip`` is the BSSID; it MUST be in exploit.allowed_targets. The
        captured file lands under the workspace for offline cracking via
        hashcat (mode 22000).
        """
        cfg = _wireless_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: wireless plugin not enabled in config."
        iface = interface or str(cfg.get("interface", "wlan0mon"))
        binary = shutil.which(str(cfg.get("hcxtools_path", "hcxdumptool"))) or "hcxdumptool"
        workspace.mkdir(parents=True, exist_ok=True)
        out_file = workspace / f"pmkid_{target_ip.replace(':', '')}.pcapng"
        argv = [
            "-i",
            iface,
            "--filtermode=2",
            f"--filterlist_ap={target_ip}",
            "-o",
            str(out_file),
            "--active_estimate=10",
        ]
        out, rc, err = _run_tool(binary, argv, timeout=60)
        if rc is None or rc != 0:
            return f"WIRELESS_PMKID_ERROR: {err or out}"
        return (
            f"WIRELESS_PMKID_RESULT: capture_complete\n"
            f"BSSID: {target_ip}\n"
            f"CAPTURE: {out_file}\n"
            f"NOTE: crack offline with: hashcat -m 22000 {out_file} wordlist.txt\n"
            f"OUTPUT:\n{out[:2000]}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def wireless_crack_pmkid(
        target_ip: str, capture_path: str, wordlist: str = "/usr/share/wordlists/rockyou.txt"
    ) -> str:
        """Crack a PMKID capture file with aircrack-ng.

        ``target_ip`` is the BSSID for audit-trail attribution (the capture
        file already targets that BSSID). Uses aircrack-ng; the wordlist must
        be readable on the operator box.
        """
        cfg = _wireless_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: wireless plugin not enabled in config."
        if not capture_path or not capture_path.strip():
            return "BLOCKED: capture_path is required."
        candidate = Path(capture_path)
        if not candidate.is_absolute():
            candidate = workspace / capture_path
        if not candidate.exists():
            return f"BLOCKED: capture not found: {candidate}"
        binary = shutil.which(str(cfg.get("aircrack_path", "aircrack-ng"))) or "aircrack-ng"
        argv = ["-w", wordlist, "-b", target_ip, str(candidate)]
        out, rc, err = _run_tool(binary, argv, timeout=300)
        if rc is None:
            return f"WIRELESS_CRACK_ERROR: {err or out}"
        return (
            f"WIRELESS_CRACK_RESULT: rc={rc}\n"
            f"BSSID: {target_ip}\n"
            f"CAPTURE: {candidate}\n"
            f"WORDLIST: {wordlist}\n"
            f"OUTPUT:\n{out[:4000]}"
        )


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return WirelessPlugin()
