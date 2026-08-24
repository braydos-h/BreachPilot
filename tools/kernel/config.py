"""Single source of truth for YAML config loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: Path) -> dict[str, Any]:
    """Load a YAML config mapping, returning an empty dict if missing.

    Shared by ``tools.config_cli``, ``tools.mcp_shared`` and
    ``tools.exploit_session`` (previously triplicated). Pure function:
    no global state, raises ``ValueError`` when the file exists but does
    not contain a mapping.
    """
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping.")
    return loaded
