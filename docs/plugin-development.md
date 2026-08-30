# Plugin Development Guide

This guide explains how to write, package, enable, and distribute plugins for
BreachPilot. It is the companion to [extension-guide.md](extension-guide.md):
that guide covers *in-tree* edits (modifying built-in modules); this one covers
the *no-recompile* extension path for capabilities that live outside the core
repository.

Plugins are managed by `tools/plugins.py` (pure stdlib: `importlib`,
`importlib.metadata`, `dataclasses`, `pathlib`, `typing`). Read that module
alongside this guide -- every symbol referenced here is defined there.

## 1. Overview

The plugin ecosystem lets an operator drop a directory (or install a Python
distribution) that contributes one or more of:

- an **attack module** (an `AttackModule` subclass the AI can select),
- **MCP tools** (`@mcp.tool()` handlers registered onto the exploit MCP server),
- a **skills directory** (extra `SKILL.md` roots for the skill registry), and/or
- a **config section** (a top-level config block treated as known by
  `ConfigValidator`, so no unknown-key warning is emitted).

Plugins are **trusted Python with full operator-box privileges**. This is a
lab build: the operator runs the engine against systems they own or are
explicitly authorized to test, on a throwaway operator box. Plugin code runs
with exactly the same privileges as the built-in `tools/mcp_tools/*` modules.
**The plugin manager does not sandbox plugin code.** It enforces two things
and only two things:

1. **Opt-in loading.** Plugins are disabled by default. A plugin is loaded
   only when it is explicitly enabled (see section 6).
2. **The safety-decorator requirement (documented, not verified).** Any MCP
   tool a plugin registers MUST wrap its handler with `ctx.require_allowlist()`
   (target-touching tools) or `ctx.audit_tool` (free-text command tools) so
   the **target-IP allowlist lock** and the **tamper-evident JSONL audit
   trail** (`exploit_workspace/<ip>/exploit_audit.jsonl`) still apply. The
   manager cannot check this at load time; it is the author's responsibility.

Because the decorators wrap the handler at registration time, the allowlist
lock + audit trail apply to plugin MCP tools **automatically** -- the author
just has to stack the decorator (see section 4).

**Hard-blocked plugin behaviours** (regardless of opt-in): log clearing,
timestomping, EDR/AV defeat, denial of service, and malware distribution.
These are policy expectations on the author. The manager itself does not
execute plugin code beyond calling `register()`, so it cannot enforce them
mechanically; do not write plugins that do these things.

## 2. Plugin layout

A filesystem plugin is a directory containing a `plugin.yaml` manifest and,
optionally, a sibling `plugin.py` module. The minimum useful plugin is just a
manifest; a plugin that contributes real behaviour adds `plugin.py`.

```
plugins/
  my_plugin/
    plugin.yaml      # manifest (identity, capabilities, enablement default)
    plugin.py        # exposes create_plugin() -> Plugin  (or a Plugin subclass)
```

`plugin.py` must expose one of:

- a `create_plugin()` factory that returns a `Plugin` instance (preferred), or
- a `Plugin` subclass named `Plugin`.

The `Plugin` ABC (`tools.plugins.Plugin`) is the contract:

```python
from tools.plugins import Plugin, PluginManifest, PluginRegistry

class MyPlugin(Plugin):
    def __init__(self) -> None:
        self.manifest = PluginManifest(name="my_plugin")

    def register(self, registry: PluginRegistry) -> None:
        # Contribute registrations here. See section 4.
        ...

def create_plugin() -> Plugin:
    return MyPlugin()
```

`Plugin.register(registry)` is the single hook where a plugin contributes its
attack modules, MCP tools, skill directories, and config sections to the
shared `PluginRegistry`. The manager wraps each `register()` call in
`try/except` so one broken plugin cannot abort the rest.

For filesystem plugins the `plugin.yaml` manifest is authoritative -- whatever
manifest the factory sets is overwritten with the parsed manifest at load time
(see `PluginManager._instantiate_from_module`). For entry-point plugins
(section 5) the manifest the plugin sets is used as-is.

A plugin directory without `plugin.py` yields a manifest-only `Plugin` whose
`register()` is a no-op. This is useful for skill-only or config-only plugins
that do not need any Python logic.

## 3. The `plugin.yaml` manifest

The manifest is parsed by a tiny pure-stdlib YAML subset parser
(`_parse_manifest_yaml`) that supports scalar key/value pairs, block lists
(`- item`), flow lists (`["a", "b"]`), one level of nested mapping for
`config_section`, `#` comments, and quoted strings. You do not need PyYAML.

Fields (`PluginManifest` dataclass):

| Field           | Type                | Default     | Meaning                                                                |
|-----------------|---------------------|-------------|------------------------------------------------------------------------|
| `name`          | `str`               | `""`        | Plugin identity. Falls back to the directory name if empty.           |
| `version`       | `str`               | `"0.0.1"`   | Semver-ish version string.                                             |
| `description`   | `str`               | `""`        | Human-readable summary shown by `--list-plugins`.                      |
| `author`        | `str`               | `""`        | Author credit.                                                         |
| `capabilities`  | `tuple[str, ...]`   | `()`        | Subset of `attack_module`, `mcp_tool`, `skill_dir`, `config`. Unknown  |
|                 |                     |             | values are dropped with a warning. Informational; not enforced.        |
| `enabled`       | `bool`              | `False`     | Manifest default. `config plugins.enabled` overrides this.            |
| `config_section`| `dict \| None`      | `None`      | Optional schema this plugin contributes (nested mapping).              |

Minimal example:

```yaml
# plugins/my_plugin/plugin.yaml
name: my_plugin
version: 0.1.0
description: Adds an example recon-report attack module and a plugin_info MCP tool.
author: Me
capabilities:
  - attack_module
  - mcp_tool
enabled: false   # opt-in; operator must enable via config
```

A `config_section` block (one level of nesting is supported by the parser):

```yaml
name: my_plugin
enabled: false
config_section:
  my_plugin:
    endpoint: https://example.invalid/api
    timeout: 30
```

## 4. The four registration hooks

`Plugin.register(registry)` receives a `PluginRegistry`
(`tools.plugins.PluginRegistry`). It exposes four registration methods. The
core registries consult the singleton (`PLUGIN_REGISTRY`) via its accessors
(`extra_module_classes`, `mcp_tool_factories`, `skill_dirs`,
`config_sections`), so anything you register here is picked up by the existing
attack-module registry, MCP server, skill loader, and config validator.

### 4a. `register_attack_module(cls)`

Append an `AttackModule` subclass (`tools.attack_modules.base.AttackModule`).
The class is appended to `registry.extra_module_classes`; the attack-module
registry instantiates it (`cls()`) when listing modules.

```python
from tools.attack_modules.base import AttackModule, ModuleContext

class ExampleReportModule(AttackModule):
    name = "example_plugin_recon_report"
    description = "Example plugin: read-only recon summary (target-locked)."
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}

    def applicability(self, ctx: ModuleContext) -> int:
        # Baseline 10: always selectable, low priority. The base scoring adds
        # +30 per matching service, +20 per matching port, +40 per matching CVE,
        # +25 for a declared vulnerable version -- override only when needed.
        return 10

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Target-locked to ctx.target_ip. Read-only here: no shell_type,
        # no privilege_level, no credentials.
        return {
            "status": "info",
            "module": self.name,
            "target_ip": ctx.target_ip,
            "summary": "example plugin recon report",
            "note": "read-only",
        }

# inside register(registry):
registry.register_attack_module(ExampleReportModule)
```

Conventions: return a structured dict; keep module names stable (tests and
orchestrators reference them); do not embed credentials in plain output; only
set `shell_type` / `privilege_level` when a real foothold is achieved.

### 4b. `register_mcp_tools(factory)`

Register a `factory(mcp, ctx) -> None` that adds `@mcp.tool()` handlers onto
the exploit MCP server. `mcp` is the MCP server object; `ctx` is a
`ToolContext` (`tools/mcp_tools/registry.py:ToolContext`) with these fields:

| Field              | Type                | Purpose                                              |
|--------------------|---------------------|------------------------------------------------------|
| `workspace`        | `Path`              | Per-target workspace root (`exploit_workspace/<ip>/`).|
| `config`           | `dict \| None`      | The loaded `config.yaml` (top-level dict).           |
| `search`           | `ExploitSearch`     | searchsploit wrapper.                                |
| `nvd`              | `NVDClient`         | NVD CVE lookup client.                               |
| `researcher`       | `WebResearcher`     | Web research provider.                               |
| `audit_tool`       | decorator           | Wraps free-text command tools: audit trail + redaction.|
| `require_allowlist`| decorator           | Wraps target-touching tools: target-IP allowlist lock + audit. |

**Every handler MUST be wrapped** with `ctx.require_allowlist()` (if it
touches the target) or `ctx.audit_tool` (if it is a free-text command tool).
Stack the decorators in the same order as `tools/mcp_tools/recon.py`:
`@mcp.tool()` on the outside, `@require_allowlist()` on the inside:

```python
def _register_my_tools(mcp, ctx):
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def plugin_info(target_ip: str) -> str:
        """Return a static info string for the target."""
        return f"PLUGIN_INFO: my_plugin v0.1.0 target={target_ip}"

# inside register(registry):
registry.register_mcp_tools(_register_my_tools)
```

This is exactly the pattern `tools/mcp_tools/recon.py` uses for `check_os`,
`quick_scan`, `run_full_recon`, etc. The `require_allowlist` decorator extracts
every destination (URL authorities, `/dev/tcp` hosts, LHOST/RHOST, scanner-verb
targets, bare IPs) via `tools.command_analyzer._extract_destinations` and
refuses any destination not in the allowlist (`EXPLOIT_TARGET` unioned with
`exploit.allowed_targets`). Because the decorator wraps the handler at
registration time, the lock + audit trail apply automatically once you stack
it -- there is nothing else to do.

### 4c. `register_skill_dir(path)`

Append a skill directory to the skill-registry roots. Each contribution is a
directory of `SKILL.md` files (YAML front matter + Markdown guidance), the
same format used by the built-in `skills/` tree.

```python
from pathlib import Path

# inside register(registry):
registry.register_skill_dir(Path(__file__).parent / "skills")
```

Skills are prompt context only -- they guide the model without adding
execution capability. They must not bypass scope, permission, approval,
command safety, workspace containment, or audit logging.

### 4d. `register_config_section(name, schema)`

Register a plugin config block name and its schema dict. Once registered,
`ConfigValidator` treats `<name>` as a known top-level key and will not emit
an unknown-key warning for it. `name` must be a non-empty string; `schema`
must be a `dict`.

```python
# inside register(registry):
registry.register_config_section(
    "my_plugin",
    {"endpoint": {"type": "str"}, "timeout": {"type": "int", "default": 30}},
)
```

This is purely an "allow this top-level config key" declaration. Deep
validation of the block's contents is the plugin's responsibility (or the
operator's); the core validator just stops warning about the key.

## 5. Discovery

The manager discovers plugins from two sources:

1. **Filesystem.** `PluginManager.discover_filesystem(search_paths)` walks each
   search path for subdirectories containing `plugin.yaml`. For each, it parses
   the manifest, then loads a sibling `plugin.py` via
   `importlib.util.spec_from_file_location` and calls `create_plugin()` (or
   instantiates a `Plugin` subclass named `Plugin`). Missing search paths are
   skipped; a plugin dir without `plugin.py` yields a manifest-only plugin.
   Discovery is tolerant -- a bad plugin is logged and skipped, never raised.

   The default search path list is `["plugins"]` (relative to the process
   working directory). Override via `config plugins.search_paths`.

2. **Python entry points.** `PluginManager.discover_entry_points()` reads
   importlib entry points in the `breachpilot.plugins` group via
   `importlib.metadata.entry_points(group=...)`. Each entry point's `.load()`
   returns a `create_plugin` factory, a `Plugin` subclass, or a `Plugin`
   instance; the manager coerces it to a `Plugin`. This is the distribution
   path: publish a wheel that declares an entry point in `breachpilot.plugins`
   and the manager will find it without any filesystem layout.

   In tests, `discover_entry_points` accepts an injectable `loader` callable
   (`loader(group) -> list[entry_point_objects]`) so the suite never touches
   the real entry-point database.

`load_all(search_paths, *, entry_points=True, entry_point_loader=None)`
combines both sources, filters to enabled plugins, and registers each.

## 6. Enablement

Plugins are **OFF by default**. The `plugins` block in `config.yaml` controls
enablement:

| Key            | Type       | Default       | Meaning                                             |
|----------------|------------|---------------|-----------------------------------------------------|
| `enabled`      | `list[str]`| (none)        | Names to load. When present, a plugin loads if its   |
|                |            |               | name is in this list OR its manifest `enabled: true`.|
| `disabled`     | `list[str]`| `[]`          | Names to never load. Overrides manifest + enabled.   |
| `search_paths` | `list[str]`| `["plugins"]` | Filesystem plugin search roots.                      |
| `entry_points` | `bool`     | `true`        | Whether to consult the `breachpilot.plugins` group.  |

The exact rule (`PluginManager._is_enabled`): a plugin is loaded iff
(`enabled` list is None -> use `manifest.enabled`; otherwise `name in enabled`
OR `manifest.enabled`) AND `name` not in `disabled`. When `enabled` is unset
and the manifest does not opt in, the plugin is **not** loaded.

Example enabling a plugin:

```yaml
# config.yaml
plugins:
  enabled:
    - example_recon_report
  disabled: []
  search_paths:
    - plugins
  entry_points: true
```

With the manifest above (`enabled: false`), this config still loads
`example_recon_report` because its name is in `plugins.enabled`. To ship a
plugin that loads with no config entry, set `enabled: true` in its manifest
(and rely on `disabled` to turn it off).

## 7. The reference plugin: `plugins/example_recon_report/`

A complete reference plugin ships under `plugins/example_recon_report/`. It
demonstrates two capabilities (`attack_module`, `mcp_tool`) with the minimum
safe shape.

**`plugin.yaml`:**

```yaml
name: example_recon_report
version: 0.1.0
description: Example plugin - a read-only recon-report attack module + plugin_info MCP tool
author: BreachPilot
capabilities: [attack_module, mcp_tool]
enabled: false   # opt-in
```

**`plugin.py`** (outline -- see the file for the full source):

```python
from pathlib import Path
from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.plugins import Plugin, PluginManifest, PluginRegistry


class ExampleReportModule(AttackModule):
    name = "example_plugin_recon_report"
    description = "Example plugin: read-only recon summary (target-locked)."
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}

    def applicability(self, ctx: ModuleContext) -> int:
        return 10  # baseline; always selectable, low priority

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        # Target-locked to ctx.target_ip. Read-only: no shell_type, no
        # privilege_level, no credentials.
        return {
            "status": "info",
            "module": self.name,
            "target_ip": ctx.target_ip,
            "summary": "example plugin recon report",
            "note": "read-only",
        }


class ExamplePlugin(Plugin):
    def __init__(self) -> None:
        manifest_path = Path(__file__).parent / "plugin.yaml"
        # (the manager re-parses plugin.yaml and overwrites this for
        # filesystem plugins, but set it so the class is usable standalone)
        self.manifest = PluginManifest(name="example_recon_report")

    def register(self, registry: PluginRegistry) -> None:
        registry.register_attack_module(ExampleReportModule)
        registry.register_mcp_tools(_register_example_tools)


def _register_example_tools(mcp, ctx):
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def plugin_info(target_ip: str) -> str:
        """Return a static info string for the target."""
        return f"PLUGIN_INFO: example_recon_report v0.1.0 target={target_ip}"


def create_plugin() -> Plugin:
    return ExamplePlugin()
```

Things to notice in the reference plugin:

- `applicability()` returns `10` so the module is always selectable but ranks
  below modules that actually match a service/port/CVE.
- `run()` is read-only and target-locked to `ctx.target_ip`; it never sets
  `shell_type` or `privilege_level` because it does not achieve a foothold.
- The MCP tool stacks `@mcp.tool()` over `@ctx.require_allowlist()` exactly as
  `tools/mcp_tools/recon.py` does, so the target-IP allowlist lock and audit
  trail apply to `plugin_info` automatically.
- `create_plugin()` is the factory the manager looks for; `plugin.py` could
  instead name the class `Plugin`.

## 8. CLI

```bash
python main.py --list-plugins
```

Lists every discovered plugin (filesystem + entry points) with its version,
description, capabilities, and a `loaded` flag (True iff the plugin name is in
`PLUGIN_REGISTRY.loaded_plugins`). Discovered-but-disabled plugins appear with
`loaded: false`; this is how an operator confirms a plugin was found before
enabling it. `load_plugins(config)` runs once during boot, before the MCP
exploit server is created, so plugin attack modules and MCP tool factories are
registered in time to be picked up.

## 9. Safety checklist for plugin authors

Before publishing a plugin, confirm every item:

- [ ] **MCP tools use the safety decorators.** Every `@mcp.tool()` handler is
      also wrapped with `@ctx.require_allowlist()` (target-touching) or
      `@ctx.audit_tool` (free-text command tools), stacked in the
      `tools/mcp_tools/recon.py` order (`@mcp.tool()` outermost).
- [ ] **Target-locked.** Target-touching tools only ever contact the single
      authorized target IP (the one in `EXPLOIT_TARGET` / `exploit.allowed_targets`).
      Attack modules operate on `ctx.target_ip` only.
- [ ] **Do not weaken the allowlist.** Never bypass `require_allowlist`, never
      mutate `exploit.allowed_targets` or `EXPLOIT_TARGET` at runtime, never
      shell out to a destination the lock would refuse.
- [ ] **Default disabled.** `plugin.yaml` ships with `enabled: false` unless
      there is a strong reason otherwise. The operator opts in via
      `config plugins.enabled`.
- [ ] **No forbidden behaviours.** No log clearing, no timestomping, no
      EDR/AV defeat, no denial of service, no malware distribution.
- [ ] **Audit trail preserved.** Do not suppress or rewrite
      `exploit_audit.jsonl`; do not redact-skipping secrets in tool output.
- [ ] **Workspace-contained artifacts.** Write generated files under the
      per-target workspace (`exploit_workspace/<ip>/`), not arbitrary
      operator-box paths, unless the capability genuinely requires it.
- [ ] **No Flow B entanglement.** Do not import `tools.recon_pipeline`,
      `tools.scope_gate`, `tools.mission`, `tools.db`, `tools.agent_loop`,
      `tools.tool_router`, `tools.risk_controller`, or `tools.safety_reviewer`
      from plugin code. Recon safety depends on those staying untouched.
- [ ] **Tolerant registration.** `register()` should not raise on missing
      optional dependencies; degrade gracefully so one bad plugin does not
      abort sibling plugins.

## 10. Relationship to `docs/extension-guide.md`

[extension-guide.md](extension-guide.md) is the **in-tree** edit-points guide:
it tells you which existing files to change when adding a defensive MCP tool,
an exploit MCP tool, an attack module, a runtime skill, recon behavior, a
goal, model routing, config keys, persistent data, agent-loop behavior, swarm
behavior, reporting, or external tool integration. Those edits
ship inside the core repository and run on the next boot.

This guide is the **external** extension path. Use a plugin when:

- the capability should be distributable independently of the core repo (a
  wheel with a `breachpilot.plugins` entry point),
- the operator wants to add an attack module / MCP tool / skill set / config
  block without modifying core files, or
- multiple operators share a capability but not a fork.

The two paths are complementary and feed the same registries. A plugin that
calls `registry.register_attack_module(cls)` lands in the same
`list_modules()` output as a built-in module added via
`tools/attack_modules/registry.py::_MODULE_CLASSES`. A plugin MCP tool factory
is invoked by `mcp_exploit_server.create_csp_server` right after the built-in
`register_*_tools` calls. A plugin skill dir is appended to the same roots the
skill loader walks. A plugin config section is treated as known by the same
`ConfigValidator`. The old edit-points guide still applies verbatim for
in-tree changes; plugins are simply the no-recompile way to extend the same
surfaces from outside the tree.
