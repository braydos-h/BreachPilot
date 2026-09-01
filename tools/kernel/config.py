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

    Wheel-cwd fix (issue #2): when ``path`` is the default sentinel
    ``Path("config.yaml")`` and no file exists at the requested location,
    the loader consults the config hierarchy (``./config.yaml`` → user
    locations → packaged defaults) via :mod:`tools.paths` instead of
    returning ``{}``. A missing *explicit* custom path (e.g.
    ``tmp_path / "nonexistent.yaml"``) still returns ``{}`` so helper/test
    callers that intentionally pass partial dicts keep the documented
    disabled-sandbox behavior. See ``tools/paths.py:resolve_config_path`` and
    ``load_effective_config``.
    """
    if not path.exists():
        if path == Path("config.yaml"):
            try:
                from tools.paths import load_effective_config  # lazy to avoid cycle

                return load_effective_config(path)
            except Exception:
                return {}
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping.")
    return loaded
