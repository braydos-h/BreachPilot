---
title: Config Profiles
description: Layered lab / recon / ci presets over config.yaml — overlays, loader usage, and the deprecated stealth block.
source: [tools/config/profiles.py, tools/config/loader.py, tools/config/schema.py]
---

# Config Profiles

`config.yaml` stays a single file with lab-build defaults (`exploit.permission:
full_access`). Layered presets in `tools/config/profiles.py` are **overlays**:
small nested dicts deep-merged onto a loaded config so one file serves three
postures without forking it. The `full_access` default is never changed — the
lab profile only re-states it (changing the default would require updating
`docs/safety-model.md` + `README.md` per CLAUDE.md).

## The three profiles

| Profile | Posture | Overlay highlights |
|---------|---------|--------------------|
| `lab` | Checked-in attack posture. Only run against systems you own or are explicitly authorized to test. | `exploit.permission: full_access`, `attack_mode: true`, `sandbox.enabled: true` |
| `recon` | Propose-only reconnaissance. | `exploit.permission: read_only`, `attack_mode: false`, `auto_post_exploit: false` |
| `ci` | Hermetic/deterministic runs. | `models.auto_update: false`, `sandbox.enabled: false`, `witness.enabled: false`, `multi_model.enabled: false`, `ultrathink/llm_reflection: false` |

Keys a profile does not mention are left exactly as the file + schema
defaults resolved them.

## Usage

```python
from tools.config.loader import load_validated_config  # or tools.config_manager

cfg = load_validated_config("config.yaml", profile="recon")
```

Or apply onto any dict (never mutates its input):

```python
from tools.config.profiles import apply_profile, get_profile, list_profiles

cfg = apply_profile(base_config, "ci")
```

`list_profiles()` / `describe_profiles()` expose names + help text;
`get_profile(name)` returns a deep copy of one overlay. Unknown names raise
`ValueError` in all three entry points.

## Deprecated: `stealth.*`

`stealth` (`rotate_ua`, `dns_over_https`) is inert/UI-only legacy — the live
block is `opsec.*` (`tools/opsec.py`). It stays in the schema/loader so
existing files keep validating, and no profile carries it. The validator
warns (never errors) when a `stealth` value deviates from schema defaults:

- `stealth` at defaults (as in the checked-in `config.yaml`) → silent.
- `stealth` customized → `"'stealth' is deprecated: ... configure opsec.* instead"`.

Canonical registry: `DEPRECATED_TOP_KEYS` in `tools/config/schema.py`.

## Related

- `docs/configuration/overview.md` — loading pipeline, precedence, validation model.
- `docs/configuration/config-reference-generated.md` — every leaf key (regenerate with `python scripts/generate_config_reference.py`).
- `tools/config/profiles.py::PROFILES` — the overlays themselves.
- `tests/test_config_profiles.py` — overlay semantics + deprecation behavior.
