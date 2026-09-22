"""Thin re-export shim — implementation lives in tools.memory_service.

Preserved so existing import paths (run_service, main re-export, tests) keep
working without behavior change.
"""

from tools.memory_service import _load_resume_state as _load_resume_state

__all__ = ["_load_resume_state"]
