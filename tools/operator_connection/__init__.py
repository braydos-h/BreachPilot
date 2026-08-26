"""Operator Box -> Victim persistent RCE + persistence connection.

Exposes ConnectionManager and implant helpers for the operator-box-side
persistence channel. Authorized-use only: every victim touch is
allowlist-gated at the MCP tool layer (@require_allowlist) and via
validate_target_or_ip before a ConnectionRecord is created.
"""

from __future__ import annotations

from tools.operator_connection.implants import (
    IMPLANT_METHODS,
    ImplantSpec,
    get_implant,
    list_implants,
    render_implant,
)
from tools.operator_connection.manager import (
    ConnectionManager,
    ConnectionRecord,
    get_connection_manager,
    reset_connection_manager,
)

__all__ = [
    "ConnectionManager",
    "ConnectionRecord",
    "get_connection_manager",
    "reset_connection_manager",
    "IMPLANT_METHODS",
    "ImplantSpec",
    "get_implant",
    "list_implants",
    "render_implant",
]
