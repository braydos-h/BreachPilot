"""Declarative, versioned tool/capability manifests (#12).

The MCP server builds tools imperatively (``register_*_tools``), but
operators, the planner, and the release gate need a static answer to "what
can this build do?" without booting a server. This module derives that
answer from the same AST seam the decorator validator uses
(:func:`tools.mcp_tools.registry._validate_mcp_tool_decorators`): every
``@mcp.tool`` function yields one :class:`ToolManifest` with its family,
allowlist posture, target parameter, and docstring summary.

``MANIFEST_VERSION`` bumps whenever the manifest shape changes; consumers
must reject unknown versions (fail closed on schema drift).
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
from dataclasses import asdict, dataclass
from typing import Any

__all__ = [
    "MANIFEST_VERSION",
    "ToolManifest",
    "collect_manifests",
    "catalog_hash",
    "manifest_scan_files",
]

MANIFEST_VERSION = 1

#: Parameter names that carry the authorization target (the allowlist lock
#: binds these; see tools/mcp_shared._allowed_target_list).
_TARGET_PARAMS = frozenset({"target_ip", "target", "host", "vm_id", "url", "domain"})


def manifest_scan_files() -> list[pathlib.Path]:
    """The exact file set the decorator validator scans (single source)."""
    pkg_dir = pathlib.Path(__file__).parent
    return (
        list(pkg_dir.glob("*.py"))
        + list((pkg_dir / "modules").glob("*.py"))
        + list((pkg_dir / "terminal").glob("*.py"))
    )


@dataclass(slots=True)
class ToolManifest:
    """Static capability record for one MCP tool (manifest v1)."""

    name: str = ""
    family: str = ""
    manifest_version: int = MANIFEST_VERSION
    requires_allowlist: bool = False
    allowlist_param: str = ""
    params: tuple[str, ...] = ()
    summary: str = ""
    lineno: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["params"] = list(self.params)
        return data


def _decorator_sources(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    sources: list[str] = []
    for deco in getattr(node, "decorator_list", []):
        try:
            sources.append(ast.unparse(deco))
        except (ValueError, SyntaxError):
            continue
    return sources


def collect_manifests(files: list[pathlib.Path] | None = None) -> list[ToolManifest]:
    """Derive one manifest per ``@mcp.tool`` function (AST-only, no imports)."""
    manifests: list[ToolManifest] = []
    for py in files if files is not None else manifest_scan_files():
        if py.name in ("registry.py", "__init__.py", "manifest.py"):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (OSError, SyntaxError):
            continue
        family = py.parent.name if py.parent.name in ("modules", "terminal") else py.stem
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            sources = _decorator_sources(node)
            lowered = [s.lower() for s in sources]
            if not any("mcp.tool" in s or ".tool(" in s for s in lowered):
                continue
            requires_allowlist = any("require_allowlist" in s for s in lowered)
            params = tuple(a.arg for a in node.args.args if a.arg not in ("self", "cls", "ctx"))
            allowlist_param = next((p for p in params if p in _TARGET_PARAMS), "")
            doc = ast.get_docstring(node) or ""
            manifests.append(
                ToolManifest(
                    name=node.name,
                    family=family,
                    requires_allowlist=requires_allowlist,
                    allowlist_param=allowlist_param,
                    params=params,
                    summary=doc.strip().splitlines()[0][:200] if doc.strip() else "",
                    lineno=node.lineno,
                )
            )
    manifests.sort(key=lambda m: (m.family, m.name))
    return manifests


def catalog_hash(manifests: list[ToolManifest]) -> str:
    """Short stable hash of the tool catalog (provenance + drift detection)."""
    bits = "|".join(f"{m.family}:{m.name}:{int(m.requires_allowlist)}:{m.allowlist_param}" for m in manifests)
    return hashlib.sha256(bits.encode("utf-8")).hexdigest()[:16]
