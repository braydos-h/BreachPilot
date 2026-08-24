---
title: Attack Modules — Registry
package: tools/attack_modules
file: tools/attack_modules/registry.py
symbols: [register_attack_module, list_modules, find_modules, _discover_attack_modules, _module_primary_service, _module_target_signature, _module_experience_confidence, find_producers, missing_prerequisites, get_module]
---

# Attack Modules — Registry (`registry.py`)

250 lines. Single source: filesystem discovery via `pkgutil.iter_modules`.

## Verified symbols

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `_MODULE_CLASSES` | `list[type[AttackModule]]` | 18 | Central registry |
| `_discover_attack_modules()` | def | 21 | `pkgutil.iter_modules(tools.attack_modules.modules)` |
| `register_attack_module` | def (decorator) | 79 | Appends if not present; idempotent |
| `list_modules()` | def | 92 | `cls()` per `_MODULE_CLASSES` + `PLUGIN_REGISTRY.extra_module_classes` |
| `find_modules(ctx, experience_store)` | def | 103 | Composite ranking |
| `_module_primary_service(mod, ctx)` | def | 145 | First present target service → `(name, version)` |
| `_module_target_signature(mod, ctx)` | def | 181 | `service:version:os` |
| `_module_experience_confidence(mod, ctx, store)` | def | 197 | Mean Bayesian confidence |
| `find_producers(artifact_kind)` | def | 221 | `produces` metadata query |
| `missing_prerequisites(mod, ctx)` | def | 233 | `requires` missing |
| `get_module(name)` | def | 240 | Case-insensitive by `mod.name` |
| `_plugin_extra_module_classes()` | def | 57 | Lazy `tools.plugins.PLUGIN_REGISTRY` consult |

## Discovery (`registry.py:21-54`)

`_discover_attack_modules()` – on import, imports `tools.attack_modules.modules`, iterates `pkgutil.iter_modules(__path__)`, imports each submodule, collects every `AttackModule` subclass (excluding `AttackModule` itself), dedupes by identity. Populated once at `registry.py:54`. No manual list edit needed – new file with `class Foo(AttackModule)` auto-registers.

`register_attack_module` decorator (`:79`) also appends if absent – opt-in for out-of-tree/test modules; collapses old 3-place edit to define+import.

`list_modules()` (`:92`) instantiates each `cls()` plus plugin extras (one bad plugin never breaks rest).

## Ranking — `find_modules` (`registry.py:103`)

Signature: `find_modules(ctx: ModuleContext, experience_store: Any|None) -> list[tuple[float, AttackModule]]` sorted descending by composite score.

| Condition | Effect |
|---|---|
| `static = mod.applicability(ctx)` (0-100) | Gate: `static<=0` skipped |
| `confidence = _module_experience_confidence(...)` | `0.5` neutral when no store/sig/data/error |
| `composite = static + (confidence-0.5)*20` | Swings ±10 around static |

Static is truth; experience only reorders among applicable modules. `min_samples` gate inside `ExperienceStore.get_all_confidences` makes thin data neutral.

### `_module_primary_service` – write/read coherence (`registry.py:145`)

The single picker shared by:

- **write side**: `AttackModule.generate_dynamic_script` records via `mutator.craft_initial(service_name, version, os_hint, module_name)`.
- **read side**: `_module_target_signature` queries `ExperienceStore.get_all_confidences(sig)` where `sig = f"{primary}:{version}:{os_hint}"`.

Picks “first declared target service actually present on target, else first declared”. Prevents pre-Tier-1.7 drift where write hardcoded `target_services[0]` (e.g. `microsoft-ds`) but read picked `smb` with different version → confidence never applied.

`_module_target_signature` returns `None` when `target_services==[]` → neutral.

`_module_experience_confidence` (`:197`) – mean of `confs[action]` where `action==mod.name or startswith(name+":")` (aggregates across `module:mutation_strategy` variants).

## Capability discovery

| Function | Line | Description |
|---|---|---|
| `find_producers(artifact_kind)` | 221 | `kind in {p.lower() for p in m.produces}` |
| `missing_prerequisites(mod, ctx)` | 233 | `{r for r in mod.requires if not _artifact_present(r, ctx)}` |
| `_artifact_present(kind, ctx)` | `base.py:58` | `credentials→bool(ctx.credentials)`, `foothold→access_achieved or sessions`, `admin_priv→privilege_level in admin/system/root` |

Used by `query_capabilities`/`get_capability_details` MCP tools and planner composition.

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_attack_modules.py` | yes | `find_modules` static ordering, `get_module` |
| `tests/test_version_aware_ranking.py` | yes | `target_versions` +25 never >100 + experience coherence |
| `tests/test_experience_ranking.py` | yes | `find_modules` with `ExperienceStore` ±10 swing |
| `tests/test_module_capability_metadata_a.py` | yes | `capability_record`, `find_producers`, `find_modules` blend |
| `tests/test_module_capability_metadata_b.py` | yes | `requires`/`produces` + `missing_prerequisites` |
| `tests/test_cross_mission_wiring.py` | yes | `experience_store` threaded to `find_modules` in vuln agent |
| `tests/test_attack_modules_api.py` | yes | MCP `run_attack_module` end-to-end |
| `tests/test_module_lint.py` | yes | Duplicate `name` detection |
