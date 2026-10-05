"""Credential redaction helpers shared by transport and runtime layers."""

from __future__ import annotations

import re
from typing import Any

from tools.kernel.audit import _mask_secret_content

_SECRET_KEY_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|password|passwd|secret|token|"
    r"api[_-]?key|authorization|auth|credential|private[_-]?key)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?)([^\s,;&\"']+)"
)
_AUTHORIZATION_ASSIGNMENT = re.compile(r"(?i)(\b(?:authorization|auth)\b\s*[\"']?\s*[:=]\s*[\"']?)([^,;\r\n]+)")
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_USERINFO = re.compile(r"(?i)(://[^/\s:@]+:)[^@/\s]+@")


def sanitize_message(message: str) -> str:
    """Redact credentials embedded in exception, command, or API text."""
    safe = _mask_secret_content(message)
    safe = _AUTHORIZATION_ASSIGNMENT.sub(r"\1[REDACTED]", safe)
    safe = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", safe)
    safe = _AUTH_SCHEME.sub(r"\1 [REDACTED]", safe)
    return _URL_USERINFO.sub(r"\1[REDACTED]@", safe)


def sanitize(value: Any) -> Any:
    """Recursively redact secret-key values and credentials embedded in text."""
    if isinstance(value, str):
        return sanitize_message(value)
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]" if isinstance(key, str) and _SECRET_KEY_PATTERNS.search(key) and item else sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    return value
