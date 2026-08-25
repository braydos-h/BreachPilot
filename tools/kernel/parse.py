# ponytail: orphan shim — pure re-export, no consumers yet outside kernel; delete if unused after 0.50
"""Parse helpers — Phase 4 shim.

``tools/exploit_agent/loop.py`` (2215 LOC) parses tool calls inline via
``_filter_and_validate_tool_calls`` + ``_parse_reasoning_block`` from
``tools.exploit_agent.tool_calls``. This kernel module re-exports those pure
functions so both flows and the future ``tools/exploit_agent/loop.py`` (<400
lines) can import from one place. See debt doc §12.

Ponytail: reuse existing helper (rung 2), no new dep.
"""

from tools.exploit_agent.context import _parse_reasoning_block  # noqa: F401
from tools.exploit_agent.tool_calls import _filter_and_validate_tool_calls  # noqa: F401

__all__ = ["_filter_and_validate_tool_calls", "_parse_reasoning_block"]
