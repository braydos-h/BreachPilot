"""Shared host-ownership condition semantics for eval and benchmark oracles."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol


class FlagResult(Protocol):
    """Minimal flag-result surface consumed by oracle conditions."""

    flag_id: str
    passed: bool


def host_owned_when_met(flag_results: Sequence[FlagResult], condition: object = "any") -> bool:
    """Evaluate a host-ownership condition without treating unknown values as ``any``.

    ``any`` and ``all`` operate over the declared flags. A list means every
    named flag is required. ``never`` explicitly represents a negative
    control: passing checks can verify an expected state, but never represent
    host ownership. ``None`` retains the historical default of ``any``.
    """
    captured = {result.flag_id for result in flag_results if result.passed}
    if isinstance(condition, (list, tuple)):
        required = [str(flag_id) for flag_id in condition]
        return all(flag_id in captured for flag_id in required) if required else bool(captured)
    if condition is None:
        condition = "any"
    if not isinstance(condition, str):
        raise ValueError("host_owned_when must be 'any', 'all', 'never', or a list of flag ids")
    normalized = condition.strip().lower()
    if normalized == "any":
        return bool(captured)
    if normalized == "all":
        return bool(flag_results) and len(captured) == len(flag_results)
    if normalized == "never":
        return False
    raise ValueError("host_owned_when must be 'any', 'all', 'never', or a list of flag ids")
