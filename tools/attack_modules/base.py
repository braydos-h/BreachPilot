"""Attack module base types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModuleContext:
    target_ip: str
    target_os: str | None = None
    services: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    workspace: Path = Path("exploit_workspace")


class AttackModule(ABC):
    """Base class for pre-packaged attack modules the AI can call via MCP."""

    name: str = ""
    description: str = ""
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []

    def applicability(self, ctx: ModuleContext) -> int:
        """Return 0-100 score indicating how applicable this module is.
        Higher = more confident this module fits the target."""
        score = 0
        svc_names = {s.get("service", "").lower() for s in ctx.services}
        svc_ports = {int(s.get("port", 0).split("/")[0]) for s in ctx.services if "/" in s.get("port", "")}
        cve_upper = {c.upper() for c in ctx.cves}

        for svc in self.target_services:
            if svc.lower() in svc_names:
                score += 30
        for port in self.target_ports:
            if port in svc_ports:
                score += 20
        for cve in self.required_cves:
            if cve.upper() in cve_upper:
                score += 40
        return min(score, 100)

    @abstractmethod
    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        """Execute the module. Returns a structured result dict."""
        ...

    def generate_python_script(self, ctx: ModuleContext) -> str:
        """Override to return a Python exploit script string."""
        return ""

    def generate_dynamic_script(self, ctx: ModuleContext, mutator: Any | None = None) -> str:
        """Generate or mutate an exploit script using the PayloadCrafter.

        Falls back to static generate_python_script() if no mutator is provided.
        """
        if mutator is None:
            return self.generate_python_script(ctx)

        # Extract service info from context. Use the shared picker so the
        # service+version recorded here (write side) agrees with what
        # find_modules queries via _module_target_signature (read side). This
        # matters for multi-service modules (e.g. SMBRelay: [microsoft-ds,
        # smb, netbios-ssn]) where recon may report a non-first-declared
        # service string -- previously this hardcoded target_services[0]
        # ('microsoft-ds'), found no matching service, and recorded an empty
        # version while the read side queried the present 'smb' with its
        # version, so the experience was silently never applied.
        from tools.attack_modules.registry import _module_primary_service

        if self.target_services:
            service_name, version = _module_primary_service(self, ctx)
        else:
            service_name, version = "unknown", ""
        os_hint = ctx.target_os or "unknown"

        payload = mutator.craft_initial(
            target_ip=ctx.target_ip,
            service_name=service_name,
            version=version,
            os_hint=os_hint,
            module_name=self.name,
        )
        return payload.script

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "target_services": self.target_services,
            "target_ports": self.target_ports,
            "required_cves": self.required_cves,
        }
