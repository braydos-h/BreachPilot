"""SNMP enumeration plugin for NetAttackAi.

Runs snmpwalk-style queries (system inventory, users, processes, open ports)
against a target's UDP/161 SNMP service, and brute-guesses community strings
from a wordlist. Pure stdlib -- snmpwalk is invoked as an external binary
(net-snmp), no pysnmp / third-party deps.

SAFETY (lab build): plugins are trusted Python with full operator-box
privileges. This plugin is OFF by default (``snmp.enabled``); every
target-touching MCP tool is wrapped with ``@require_allowlist`` so the
target-IP allowlist lock + JSONL audit trail apply. It performs no log
clearing, timestomping, EDR/AV defeat, DoS, or malware.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.snmp")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"

# ponytail: small static table of common community strings; snmpwalk probes are
# cheap and 'public' wins on most lab targets. A larger wordlist is a config/arg
# concern, not a code concern.
_DEFAULT_COMMUNITY_LIST: list[str] = [
    "public", "private", "community", "admin", "snmp", "read", "write", "cisco", "default", "secret",
]


def _snmp_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("snmp") or {}
    if not isinstance(cfg_block, dict):
        return {}
    return cfg_block


def _snmp_timeout(config: dict[str, Any] | None) -> int:
    raw = _snmp_cfg(config).get("timeout", 10)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 10


def _snmp_version(config: dict[str, Any] | None) -> str:
    return str(_snmp_cfg(config).get("default_version", "2c") or "2c")


def _run_snmpwalk(
    ip: str,
    community: str,
    version: str = "2c",
    oid: str = "",
    timeout: int = 10,
    runner: Callable[[list[str], int], tuple[int, str, str]] | None = None,
) -> tuple[int, str]:
    """Run ``snmpwalk`` against ``ip``. Returns (returncode, stdout+stderr capped to 4000 chars)."""
    argv: list[str] = ["snmpwalk", "-v", version, "-c", community, ip]
    if oid:
        argv.append(oid)
    if runner is not None:
        rc, stdout, stderr = runner(argv, timeout)
        return rc, (stdout + stderr)[:4000]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "snmpwalk not found — install net-snmp"
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)
    return proc.returncode, (proc.stdout + proc.stderr)[:4000]


def _run_community_walk(
    ip: str,
    community: str,
    version: str = "2c",
    oid: str = "",
    timeout: int = 10,
    runner: Callable[[list[str], int], tuple[int, str, str]] | None = None,
) -> tuple[int, str]:
    """Probe a single community string against the SNMP system MIB (1.3.6.1.2.1.1)."""
    return _run_snmpwalk(ip, community, version=version, oid=oid or "1.3.6.1.2.1.1", timeout=timeout, runner=runner)


def _guess_communities(
    ip: str,
    wordlist: list[str],
    timeout: int = 10,
    version: str = "2c",
    runner: Callable[[list[str], int], tuple[int, str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Probe each community string; stop after the first one that works.

    A community "works" when snmpwalk returns 0 AND produced non-empty output
    (a real answer from the target, not an empty success).
    """
    results: list[dict[str, Any]] = []
    for c in wordlist:
        if not c or not c.strip():
            continue
        rc, output = _run_community_walk(ip, c, version=version, timeout=timeout, runner=runner)
        works = rc == 0 and bool(output.strip())
        results.append({"community": c, "works": works})
        if works:
            break
    return results


class SNMPEnumeration(AttackModule):
    name = "SNMPEnumeration"
    description = "Enumerate SNMP services for system info, users, processes, and open ports via community strings"
    target_services = ["snmp"]
    target_ports = [161]
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "SNMP enumeration via snmpwalk over UDP 161 using a community "
                "string. Community strings are often defaulted to 'public' or "
                "'private' on misconfigured devices; successful read access "
                "leaks system inventory, users, processes, and open ports."
            ),
            evidence=[f"SNMP enumeration candidate: {ctx.target_ip} (UDP 161, community string)"],
            references=[
                "https://www.thehacker.recipes/a-d/movement/discovery/spidering",
                "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp.html",
            ],
            suggested_command="snmpwalk -v2c -c public " + ctx.target_ip + " 1.3.6.1.2.1.1",
        )

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import subprocess, sys, json
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
community = sys.argv[2] if len(sys.argv) > 2 else "public"
version = sys.argv[3] if len(sys.argv) > 3 else "2c"
results = {{"walk": ""}}
try:
    out = subprocess.run(["snmpwalk", "-v", version, "-c", community, host, "1.3.6.1.2.1.1"], capture_output=True, text=True, timeout=30)
    results["walk"] = out.stdout[:4000]
    if out.returncode != 0:
        results["error"] = out.stderr[:1000]
except Exception as e:
    results["error"] = str(e)
print(json.dumps(results))
"""


class SnmpPlugin(Plugin):
    """Plugin wrapper that registers the SNMP attack module + MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_attack_module(SNMPEnumeration)
        registry.register_config_section(
            "snmp",
            {
                "enabled": {"type": "bool", "default": False},
                "timeout": {"type": "int", "default": 10},
                "default_version": {"type": "str", "default": "2c"},
                "community_env": {"type": "str", "default": "SNMP_COMMUNITY"},
            },
        )
        registry.register_mcp_tools(_register_snmp_tools)


def _register_snmp_tools(mcp: Any, ctx: Any) -> None:
    """Register SNMP MCP tools. Decorators stack bottom-up: require_allowlist
    gates the raw handler, then mcp.tool registers it -- same as zap_scan."""
    require_allowlist = ctx.require_allowlist
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def snmp_enum_target(target_ip: str, community: str = "", oid: str = "", version: str = "") -> str:
        """Enumerate an SNMP service with snmpwalk (community = community string, default from SNMP_COMMUNITY env or 'public'; version default '2c'; optional OID like 1.3.6.1.2.1.1). Returns system/users/process inventory. Target-locked to target_ip."""
        cfg = _snmp_cfg(config)
        if cfg.get("enabled") is not True:
            return "BLOCKED: snmp plugin not enabled in config (snmp.enabled)."
        community = community.strip() or os.environ.get(cfg.get("community_env", "SNMP_COMMUNITY")) or "public"
        version = version.strip() or cfg.get("default_version", "2c")
        rc, output = _run_community_walk(target_ip, community, version=version, oid=oid.strip(), timeout=_snmp_timeout(config))
        if rc != 0:
            return f"SNMP_ENUM_ERROR: returncode {rc}\n{output}"
        return (
            f"SNMP_ENUM_RESULT:\n"
            f"TARGET: {target_ip}\n"
            f"COMMUNITY: {community}\n"
            f"VERSION: {version}\n"
            f"OID: {oid.strip() or '(root)'}\n"
            f"{output}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def snmp_crack_community(target_ip: str, wordlist: str = "") -> str:
        """Brute-guess the SNMP community string from a wordlist (default: a small built-in list of common community strings) via snmpwalk probes. Target-locked; attempts only work against the allowlisted target."""
        cfg = _snmp_cfg(config)
        if cfg.get("enabled") is not True:
            return "BLOCKED: snmp plugin not enabled in config (snmp.enabled)."
        if wordlist.strip():
            try:
                tokens = [line.strip() for line in Path(wordlist.strip()).read_text(encoding="utf-8").splitlines()]
                tokens = [t for t in tokens if t]
                # ponytail: cap at 100 -- brute-forcing an unbounded file means
                # up to timeout-per-probe against the target; 100 is a sane bound.
                tokens = tokens[:100]
            except Exception as exc:  # noqa: BLE001
                return f"SNMP_COMMUNITY_ERROR: could not read wordlist: {exc}"
        else:
            tokens = list(_DEFAULT_COMMUNITY_LIST)
        results = _guess_communities(target_ip, tokens, timeout=_snmp_timeout(config), version=cfg.get("default_version", "2c"))
        lines = [f"COMMUNITY: {r['community']} -> {'OK' if r['works'] else 'FAIL'}" for r in results]
        worked = [r for r in results if r["works"]]
        if not worked:
            return "SNMP_COMMUNITY_ERROR: no community string worked\n" + "\n".join(lines)
        return f"SNMP_COMMUNITY_RESULT: {worked[0]['community']} (worked)\n" + "\n".join(lines)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return SnmpPlugin()
