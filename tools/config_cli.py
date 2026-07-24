"""CLI configuration and startup API-key helpers."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from tools.api_key_store import DEFAULT_API_KEY_FILE, bootstrap_api_keys
from tools.attack_ui import AttackUi

ui = AttackUi(plain=False)

def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping.")
    return loaded

def bootstrap_startup_api_keys(args: argparse.Namespace, *, prompt: bool = False) -> None:
    """Load saved provider API keys and optionally prompt for missing values."""

    config = load_config(args.config)
    result = bootstrap_api_keys(
        config,
        store_path=Path(getattr(args, "api_key_file", DEFAULT_API_KEY_FILE)),
        prompt=prompt and not bool(getattr(args, "no_api_key_prompt", False)),
        force_prompt=bool(getattr(args, "setup_api_keys", False)),
    )
    if result.loaded:
        ui.info(f"Loaded provider API key(s) from {result.store_path}: {', '.join(result.loaded)}")
    if result.saved:
        ui.info(f"Saved provider API key(s) to {result.store_path}: {', '.join(result.saved)}")
    if result.missing and (prompt or bool(getattr(args, "setup_api_keys", False))):
        ui.warning(
            "Missing provider API key(s): "
            + ", ".join(result.missing)
            + ". MCP research tools that require provider APIs will stay disabled."
        )

