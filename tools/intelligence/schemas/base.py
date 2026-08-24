"""Base schema plumbing: validation results, repair/coerce lifecycle, telemetry.

Typed, stdlib-only handling of structured model output. Every schema follows
the same contract: validate -> repair ONCE -> fall back safely -> log telemetry.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

_TELEMETRY: list[dict] = []


@dataclass(slots=True)
class ValidationResult:
    """Outcome of a schema validation/repair pass."""

    valid: bool
    errors: list[str]
    repaired: bool = False
    message: str = ""


def log_validation(schema_name: str, ok: bool, errors: list[str], source: str = "", path: Optional[str] = None) -> None:
    """Append a telemetry entry; optionally also write JSONL to ``path``."""
    entry = {
        "schema": schema_name,
        "ok": ok,
        "errors": list(errors),
        "source": source,
    }
    _TELEMETRY.append(entry)
    if path is not None:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def dump_telemetry() -> list[dict]:
    """Return a copy of all telemetry entries recorded this process."""
    return list(_TELEMETRY)


def _safe_enum(value: Any, enum_class: type[Enum], default: Enum) -> Enum:
    """Coerce ``value`` to ``enum_class``, falling back to ``default``."""
    if isinstance(value, enum_class):
        return value
    try:
        return enum_class(value)
    except (ValueError, TypeError):
        return default


def _require_str(d: dict, key: str, max_len: int) -> str:
    """Return ``d[key]`` if a non-empty string no longer than ``max_len``, else ''."""
    value = d.get(key)
    if isinstance(value, str) and value.strip() and len(value) <= max_len:
        return value.strip()
    return ""


def _clamp_float(v: Any, lo: float, hi: float) -> float:
    """Coerce ``v`` to float and clamp into ``[lo, hi]``."""
    try:
        return min(hi, max(lo, float(v)))
    except (TypeError, ValueError):
        return lo


class BaseSchema(ABC):
    """Lifecycle contract for structured model-output schemas.

    ``coerce`` is the one-call entry point: validate, repair once if needed,
    and return an object — raising ``ValueError`` only when repair could not
    make the raw dict valid, so callers can fall back to their default.
    """

    @abstractmethod
    def validate(self, raw: dict) -> ValidationResult:
        """Return whether ``raw`` conforms, with the collected errors."""

    @abstractmethod
    def repair(self, raw: dict, errors: list[str]) -> dict:
        """Return a best-effort repaired copy of ``raw``; append notes to ``errors``."""

    @abstractmethod
    def coerce(self, raw: dict) -> Any:
        """Validate (repairing once) and build the typed object; raise on final failure."""

    def safe_load(self, raw: dict) -> tuple[Optional[Any], ValidationResult]:
        """Never raises: returns ``(object, result)`` or ``(None, result)``."""
        result = self.validate(raw)
        if result.valid:
            try:
                return self.coerce(raw), result
            except Exception as exc:  # noqa: BLE001 - safe_load must never raise
                return None, ValidationResult(valid=False, errors=[str(exc)], repaired=result.repaired)
        repaired = self.repair(dict(raw), list(result.errors))
        repaired_result = self.validate(repaired)
        repaired_result.repaired = True
        if repaired_result.valid:
            try:
                return self.coerce(repaired), repaired_result
            except Exception as exc:  # noqa: BLE001
                return None, ValidationResult(valid=False, errors=[str(exc)], repaired=True)
        return None, ValidationResult(valid=False, errors=list(result.errors) + repaired_result.errors, repaired=True)

    @staticmethod
    def _str_list(value: Any) -> list[str]:
        """Coerce ``value`` to a list of strings; anything else becomes []."""
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]
