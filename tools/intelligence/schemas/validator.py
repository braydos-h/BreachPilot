"""Safe loading of model JSON output: extract -> parse -> validate -> repair once -> fallback.

Never silently accept malformed model output. Every load is logged to
telemetry regardless of outcome.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from .base import BaseSchema, ValidationResult, log_validation


def extract_json_block(text: str) -> Optional[str]:
    """Find the first balanced {..} or [..] block in arbitrary model text.

    Strips ```json fences and ignores prose wrappers such as
    "Here is the result:". Returns None when no block exists.
    """
    if not isinstance(text, str):
        return None
    start = None
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        elif ch == "[":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "]":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    if start is not None and depth > 0:
        return text[start:]
    return None


def parse_json_block(text: str) -> Optional[Any]:
    """Extract the JSON block from ``text`` and json.loads it; None on failure."""
    block = extract_json_block(text)
    if block is None:
        return None
    try:
        return json.loads(block)
    except json.JSONDecodeError:
        return None


class SafeSchemaLoader:
    """Load model text into a typed object with validate->repair-once->fallback."""

    def __init__(self, validator: BaseSchema, default_factory: Callable[[], Any], schema_name: str):
        self.validator = validator
        self.default_factory = default_factory
        self.schema_name = schema_name

    def load(self, raw_json_str: str) -> tuple[Any, ValidationResult]:
        """Parse and validate ``raw_json_str``; never raises, always logs telemetry."""
        block = extract_json_block(raw_json_str)
        if block is None:
            result = ValidationResult(valid=False, errors=["no JSON block found"])
            log_validation(self.schema_name, False, result.errors, source="raw_text")
            return self.default_factory(), result

        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            result = ValidationResult(valid=False, errors=["unparseable"])
            log_validation(self.schema_name, False, result.errors, source="raw_text")
            return self.default_factory(), result

        if not isinstance(parsed, dict):
            result = ValidationResult(valid=False, errors=["expected a JSON object"])
            log_validation(self.schema_name, False, result.errors, source="raw_text")
            return self.default_factory(), result

        first = self.validator.validate(parsed)
        if first.valid:
            try:
                obj = self.validator.coerce(parsed)
            except Exception as exc:  # noqa: BLE001 - loader never raises
                result = ValidationResult(valid=False, errors=[str(exc)])
                log_validation(self.schema_name, False, result.errors, source="raw_text")
                return self.default_factory(), result
            log_validation(self.schema_name, True, [], source="raw_text")
            return obj, first

        repair_errors = list(first.errors)
        repaired = self.validator.repair(dict(parsed), repair_errors)
        second = self.validator.validate(repaired)
        second.repaired = True
        second.errors = repair_errors + second.errors
        if second.valid:
            try:
                obj = self.validator.coerce(repaired)
            except Exception as exc:  # noqa: BLE001
                second.valid = False
                second.errors.append(str(exc))
            else:
                log_validation(self.schema_name, True, repair_errors, source="raw_text")
                return obj, second
        log_validation(self.schema_name, False, second.errors, source="raw_text")
        return self.default_factory(), second
