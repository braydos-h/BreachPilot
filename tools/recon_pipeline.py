"""Deprecated: use tools.recon — shim for one release."""

import sys
from types import ModuleType

import tools.recon.config as _cfg
import tools.recon.enumerator as _enum
import tools.recon.pipeline as _pipe
import tools.recon.scanner as _scan
from tools.recon.config import HostReconResult, ReconConfig, ServiceInfo, ToolAvailability  # noqa: F401
from tools.recon.enumerator import SecondaryEnumerator  # noqa: F401
from tools.recon.pipeline import ReconPipeline  # noqa: F401
from tools.recon.scanner import PrimaryReconScanner, _kill_process, run_command  # noqa: F401

# Mapping of shim attribute -> canonical modules that also hold that name.
# Patching the shim (e.g. in tests) must propagate to the real implementation
# modules, otherwise ``from tools.recon.scanner import run_command`` keeps the
# old object and mocks have no effect (Windows nmap-not-found vs Linux).
_CANONICAL_MAP: dict[str, tuple[ModuleType, ...]] = {
    "HostReconResult": (_cfg,),
    "ReconConfig": (_cfg,),
    "ServiceInfo": (_cfg,),
    "ToolAvailability": (_cfg,),
    "SecondaryEnumerator": (_enum,),
    "ReconPipeline": (_pipe,),
    "PrimaryReconScanner": (_scan,),
    "_kill_process": (_scan,),
    "run_command": (_scan, _enum),
    "os": (_scan,),
    "signal": (_scan,),
}


class _ReconPipelineProxy(ModuleType):
    """Proxy so ``patch('tools.recon_pipeline.X')`` also patches canonical."""

    def __setattr__(self, name: str, value) -> None:  # type: ignore[override]
        object.__setattr__(self, name, value)
        for mod in _CANONICAL_MAP.get(name, ()):
            try:
                setattr(mod, name, value)
            except Exception:
                pass

    def __getattr__(self, name: str):  # type: ignore[override]
        for mod in (_cfg, _enum, _pipe, _scan):
            if hasattr(mod, name):
                return getattr(mod, name)
        raise AttributeError(name)


_proxy = _ReconPipelineProxy(__name__)
_proxy.__dict__.update(sys.modules[__name__].__dict__)
_proxy.__spec__ = sys.modules[__name__].__spec__  # type: ignore[attr-defined]
sys.modules[__name__] = _proxy
