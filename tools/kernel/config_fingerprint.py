"""Canonical fingerprints for checking MCP child configuration identity.

The WebUI can change ``api.serve_webui`` in memory when ``--web`` starts the
app. That switch affects static-file serving only; MCP children never consume
it. All other config entries participate in the fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

__all__ = ["ConfigFingerprintMismatch", "config_fingerprint", "verify_config_fingerprint"]


class ConfigFingerprintMismatch(RuntimeError):
    """Raised before MCP tool registration when child config has drifted."""


def config_fingerprint(config: Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest of config values used by MCP children.

    The config is encoded in memory only. No config values or digest details
    are included in errors or logs. JSON's sorted mapping keys and compact
    separators make YAML key order and whitespace irrelevant. Paths and YAML
    date values are normalized to strings; tuples become lists, matching the
    values produced by YAML loading.
    """
    canonical_config = dict(config)
    api_config = canonical_config.get("api")
    if isinstance(api_config, Mapping) and "serve_webui" in api_config:
        api_without_webui = dict(api_config)
        api_without_webui.pop("serve_webui", None)
        if api_without_webui:
            canonical_config["api"] = api_without_webui
        else:
            canonical_config.pop("api", None)

    def _normalize(value: Any) -> str:
        if isinstance(value, (Path, date, datetime)):
            return str(value)
        raise TypeError(f"Unsupported config value type: {type(value).__name__}")

    payload = json.dumps(
        canonical_config,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_normalize,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_config_fingerprint(config: Mapping[str, Any], expected: str | None) -> None:
    """Fail before MCP setup if loaded config differs from the accepted copy."""
    if expected is None:
        return
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ConfigFingerprintMismatch("MCP configuration fingerprint is invalid; refusing tool registration.")
    actual = config_fingerprint(config)
    if actual != expected:
        raise ConfigFingerprintMismatch(
            "MCP configuration no longer matches the accepted run; refusing tool registration."
        )
