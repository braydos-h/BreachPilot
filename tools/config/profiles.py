"""Layered config profiles — lab / recon / ci presets over ``config.yaml``.

``config.yaml`` + ``tools/config/schema.py`` carry every key with lab-build
defaults (``exploit.permission: full_access``). These profiles are
*overlays*: small nested dicts deep-merged onto a loaded config so one file
serves three postures without forking it:

- ``lab`` — the checked-in attack posture (explicit pins for the
  safety-relevant keys; never changes the ``full_access`` default, only
  re-states it).
- ``recon`` — propose-only recon: ``read_only`` + ``attack_mode: false`` so
  the agent gathers intel without executing anything.
- ``ci`` — hermetic/deterministic: no registry auto-update, no sandbox,
  no witness, no peer consultation, no deep-reasoning extras.

Usage::

    from tools.config.profiles import apply_profile
    from tools.config.loader import load_validated_config

    cfg = load_validated_config("config.yaml", profile="recon")

``apply_profile`` never mutates its input — it returns a new dict. Unknown
profile names raise ``ValueError``. The deprecated ``stealth`` block
(``DEPRECATED_TOP_KEYS`` in ``tools/config/schema.py``) is intentionally
absent from every profile: new posture work targets ``opsec.*``.
"""

from __future__ import annotations

import copy
from typing import Any

# Profile name -> human description (used by --help surfaces and docs).
PROFILE_DESCRIPTIONS: dict[str, str] = {
    "lab": "Checked-in attack posture: full_access exploit permission, "
    "attack_mode on, sandbox-contained execution. Only run against systems "
    "you own or are explicitly authorized to test.",
    "recon": "Propose-only reconnaissance: read_only permission, attack_mode "
    "off, no auto post-exploit. The agent gathers intel and proposes attacks "
    "without executing them.",
    "ci": "Hermetic CI posture: deterministic model registry, no sandbox, "
    "no witness watcher, no peer consultation. For mocked/offline test runs.",
}

# Profile name -> nested overlay deep-merged onto the loaded config.
# Keys not mentioned here are left exactly as the file + schema defaults
# resolved them. ``exploit.permission: full_access`` is re-stated by the lab
# profile, never changed — see CLAUDE.md "Things To Watch Out For".
PROFILES: dict[str, dict[str, Any]] = {
    "lab": {
        "exploit": {
            "permission": "full_access",
            "attack_mode": True,
            "require_explicit_allowlist": True,
        },
        "sandbox": {
            "enabled": True,
        },
    },
    "recon": {
        "exploit": {
            "permission": "read_only",
            "attack_mode": False,
            "auto_post_exploit": False,
        },
        "swarm": {
            "exploit_parallel": False,
        },
    },
    "ci": {
        "models": {
            "auto_update": False,
        },
        "sandbox": {
            "enabled": False,
        },
        "witness": {
            "enabled": False,
        },
        "multi_model": {
            "enabled": False,
        },
        "reasoning": {
            "ultrathink": False,
            "llm_reflection": False,
        },
        "research": {
            "assistant": {
                "automatic": False,
            },
        },
    },
}


def list_profiles() -> list[str]:
    """Return the available profile names in definition order."""
    return list(PROFILES)


def describe_profiles() -> dict[str, str]:
    """Return ``{profile_name: description}`` for help text and docs."""
    return dict(PROFILE_DESCRIPTIONS)


def get_profile(name: str) -> dict[str, Any]:
    """Return a deep copy of the ``name`` overlay. Raises ``ValueError``."""
    key = str(name or "").strip().lower()
    if key not in PROFILES:
        raise ValueError(f"Unknown config profile {name!r} (expected one of: {', '.join(list_profiles())}).")
    return copy.deepcopy(PROFILES[key])


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` onto ``base`` in place; return ``base``."""
    for key, value in overlay.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def apply_profile(config: dict[str, Any] | None, name: str) -> dict[str, Any]:
    """Return a new config dict with the ``name`` profile overlay applied.

    The input is never mutated. ``config`` may be ``None`` (treated as ``{}``).
    Raises ``ValueError`` for unknown profile names.
    """
    merged = copy.deepcopy(config or {})
    _deep_merge(merged, get_profile(name))
    return merged
