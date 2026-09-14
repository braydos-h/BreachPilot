"""OpenAPI import into an operation graph (#24, slice 1: OpenAPI only).

Parses an OpenAPI 3.x document (JSON or YAML) into typed :class:`Operation`
records and links them into an :class:`OperationGraph` by shared tags,
shared parameter names, and path-prefix relations. Postman/HAR/Burp
importers follow the same record shape (follow-up).

Security notes: the document is untrusted input — parsing never executes
servers/URLs, resolves only local ``#/`` refs, and caps size/operations so
a hostile spec cannot exhaust memory. Auth requirements are recorded as
data for session-profile wiring (#23), never executed here.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "IMPORTER_VERSION",
    "Operation",
    "OperationGraph",
    "parse_openapi",
    "load_openapi_file",
    "MAX_OPERATIONS",
    "MAX_SPEC_BYTES",
]

IMPORTER_VERSION = 1

#: DoS caps for hostile specs.
MAX_SPEC_BYTES = 5_000_000
MAX_OPERATIONS = 5_000

_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


@dataclass(slots=True)
class Operation:
    """One API operation: method + path + auth + parameters."""

    operation_id: str = ""
    method: str = ""
    path: str = ""
    tags: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    requires_auth: bool = False
    auth_schemes: tuple[str, ...] = ()
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tags"] = list(self.tags)
        data["parameters"] = list(self.parameters)
        data["auth_schemes"] = list(self.auth_schemes)
        return data


@dataclass
class OperationGraph:
    """Operations plus adjacency (shared tags/params/path prefix)."""

    operations: list[Operation] = field(default_factory=list)
    edges: dict[str, list[str]] = field(default_factory=dict)  # op_id -> [op_id]

    def to_dict(self) -> dict[str, Any]:
        return {"operations": [o.to_dict() for o in self.operations], "edges": dict(self.edges)}

    @property
    def operation_ids(self) -> list[str]:
        return [o.operation_id for o in self.operations]


def _load_document(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        import yaml  # local import: only needed for YAML specs

        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("OpenAPI document must be a JSON/YAML object")
    return data


def _resolve_local_ref(ref: str, doc: dict[str, Any]) -> Any:
    """Resolve ``#/a/b`` JSON pointers only (no URLs, no files)."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def parse_openapi(text: str, *, source: str = "") -> OperationGraph:
    """Parse an OpenAPI 3.x document into an operation graph."""
    _ = source
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise ValueError(f"spec exceeds {MAX_SPEC_BYTES} bytes")
    doc = _load_document(text)
    version = str(doc.get("openapi", doc.get("swagger", "")) or "")
    if not version.startswith(("3.", "2.")):
        raise ValueError(f"unsupported spec version {version!r} (want OpenAPI 2.x/3.x)")
    security_schemes: dict[str, Any] = {}
    components = doc.get("components", {}) if isinstance(doc.get("components"), dict) else {}
    if isinstance(components.get("securitySchemes"), dict):
        security_schemes = components["securitySchemes"]
    global_security = doc.get("security", []) if isinstance(doc.get("security"), list) else []

    graph = OperationGraph()
    paths = doc.get("paths", {}) if isinstance(doc.get("paths"), dict) else {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        if str(path).startswith("x-"):
            continue
        shared_params = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method in _METHODS:
            raw = item.get(method)
            if not isinstance(raw, dict):
                continue
            if len(graph.operations) >= MAX_OPERATIONS:
                raise ValueError(f"spec exceeds {MAX_OPERATIONS} operations")
            op_id = str(raw.get("operationId", f"{method}_{path}"))
            params: list[str] = []
            for plist in (shared_params, raw.get("parameters", [])):
                if not isinstance(plist, list):
                    continue
                for param in plist:
                    if isinstance(param, dict) and "$ref" in param:
                        resolved = _resolve_local_ref(str(param["$ref"]), doc)
                        param = resolved if isinstance(resolved, dict) else {}
                    if isinstance(param, dict) and param.get("name"):
                        params.append(str(param["name"]))
            op_security = raw.get("security", global_security)
            schemes: list[str] = []
            if isinstance(op_security, list):
                for requirement in op_security:
                    if isinstance(requirement, dict):
                        schemes.extend(str(k) for k in requirement)
            graph.operations.append(
                Operation(
                    operation_id=op_id,
                    method=method.upper(),
                    path=str(path),
                    tags=tuple(str(t) for t in (raw.get("tags", []) or []) if isinstance(t, str)),
                    parameters=tuple(dict.fromkeys(params)),
                    requires_auth=bool(schemes),
                    auth_schemes=tuple(dict.fromkeys(schemes)),
                    summary=str(raw.get("summary", "") or "")[:200],
                )
            )
    graph.operations.sort(key=lambda o: (o.path, o.method))
    _link(graph)
    return graph


def _link(graph: OperationGraph) -> None:
    """Adjacency: shared tags, shared params, path-prefix relations."""
    ops = graph.operations
    edges: dict[str, set[str]] = {o.operation_id: set() for o in ops}
    for i, left in enumerate(ops):
        for right in ops[i + 1 :]:
            linked = False
            if set(left.tags) & set(right.tags):
                linked = True
            elif set(left.parameters) & set(right.parameters):
                linked = True
            else:
                lp, rp = left.path.rstrip("/"), right.path.rstrip("/")
                if lp and rp and (lp == rp or lp.startswith(rp + "/") or rp.startswith(lp + "/")):
                    linked = True
            if linked:
                edges[left.operation_id].add(right.operation_id)
                edges[right.operation_id].add(left.operation_id)
    graph.edges = {k: sorted(v) for k, v in edges.items()}


def load_openapi_file(path: str) -> OperationGraph:
    """Load a spec file (size-capped) into an operation graph."""
    from pathlib import Path

    file_path = Path(path)
    if file_path.stat().st_size > MAX_SPEC_BYTES:
        raise ValueError(f"spec file exceeds {MAX_SPEC_BYTES} bytes")
    return parse_openapi(file_path.read_text(encoding="utf-8"), source=str(file_path))
