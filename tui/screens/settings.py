"""Settings screen — configure default paths, safety toggles, theme, and more."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button, Input, Switch, Select, Static, Label,
)
from textual import on

from tui.themes import set_icon_mode
from tui.widgets import HelpFooter

SETTINGS_FILE = Path("research_workspace/settings.json")


def _load_settings() -> dict:
    """Load settings from JSON file, returning defaults if missing."""
    defaults = {
        "unicode_icons": True,
        "ollama_host": "http://localhost:11434",
        "default_model": "glm",
        "rotate_ua": False,
        "doh": False,
        "default_risk": "standard_authorized",
        "workspace_dir": "research_workspace",
        "auto_refresh": 5,
        "multi_model_consult": False,
    }
    try:
        if SETTINGS_FILE.exists():
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            defaults.update(data)
    except (json.JSONDecodeError, OSError):
        pass
    return defaults


def _model_select_options(selected: str | None = None) -> tuple[list[tuple[str, str]], str]:
    """Build model Select options from config metadata, with stable defaults."""
    registry: dict[str, str] = {}
    info: Mapping[str, Any] = {}

    try:
        from tools.config_manager import load_validated_config

        config = load_validated_config()
        models = config.get("models", {}) if isinstance(config, Mapping) else {}
        raw_registry = models.get("registry", {}) if isinstance(models, Mapping) else {}
        raw_info = models.get("info", {}) if isinstance(models, Mapping) else {}
        if isinstance(raw_registry, Mapping):
            registry = {str(alias): str(model_id) for alias, model_id in raw_registry.items()}
        if isinstance(raw_info, Mapping):
            info = raw_info
    except Exception:
        registry = {}
        info = {}

    try:
        from tools.model_router import (
            DEFAULT_MODEL_REGISTRY,
            format_model_choice,
            model_choice_items,
        )

        if not registry:
            registry = dict(DEFAULT_MODEL_REGISTRY)
        options = model_choice_items(registry, info)
        if selected and selected not in {value for _, value in options}:
            options.append((format_model_choice(selected, registry=registry, registry_info=info), selected))
    except Exception:
        if not registry:
            registry = {
                "kimi": "kimi-k2.6:cloud",
                "deepseek": "deepseek-v4-pro:cloud",
                "deepseek_flash": "deepseek-v4-flash:cloud",
                "glm": "glm-5.2:cloud",
                "minimax": "minimax-m3:cloud",
            }
        options = [(f"{alias} | {model_id}", alias) for alias, model_id in registry.items()]

    if not options:
        options = [("glm | GLM-5.2 | 976K ctx | glm-5.2:cloud", "glm")]
    values = {value for _, value in options}
    effective_selected = selected if selected in values else options[0][1]
    return options, effective_selected


# Operator-facing keys the Settings screen is allowed to write into config.yaml.
# Deliberately EXCLUDES exploit.permission / exploit.attack_mode / max_pivot_depth /
# timeouts -- those are safety controls set by the operator directly in config.yaml
# or via the CLI, never from this UI. (Tier 0.7 Tranche A.)
_CONFIG_SYNC_KEYS = (
    ("ollama", "host", "ollama_host"),
    ("models", "default_alias", "default_model"),
    ("stealth", "rotate_ua", "rotate_ua"),
    ("stealth", "dns_over_https", "doh"),
    ("multi_model", "enabled", "multi_model_consult"),
)


def _sync_config_keys(settings: dict) -> bool:
    """Merge operator-facing keys into config.yaml if it exists.

    Loads the existing config.yaml verbatim (preserving every key, including the
    safety-critical ``exploit.*`` section), overlays only the permitted keys,
    and writes it back. Returns False (no-op) if config.yaml is absent -- the
    Settings screen never silently materializes a config.yaml. ``exploit.permission``
    and ``exploit.attack_mode`` are never touched, so the operator's safety stance
    is preserved exactly.
    """
    from pathlib import Path as _Path

    config_path = _Path("config.yaml")
    if not config_path.exists():
        return False

    try:
        from tools.config_manager import ConfigValidator
    except Exception:
        return False

    try:
        validator = ConfigValidator(config_path)
        validator.load()  # raw load; preserves all existing keys
        cfg = validator.config
        for section, key, src_key in _CONFIG_SYNC_KEYS:
            if src_key not in settings:
                continue
            if not isinstance(cfg.get(section), dict):
                cfg[section] = {}
            cfg[section][key] = settings[src_key]
        validator.save()
        return True
    except Exception:
        # Settings save must never raise into the TUI; the settings.json write
        # already succeeded. Config-sync failures are non-fatal.
        return False


def _save_settings(settings: dict) -> bool:
    """Save UI prefs to settings.json and propagate operator-safe keys to config.yaml.

    Two stores, by design:
    - ``research_workspace/settings.json`` holds pure-UI prefs (icons, auto-refresh,
      default risk profile, workspace dir) -- these never affect safety or engine.
    - ``config.yaml`` holds the behavior-defining keys. Only operator-facing
      keys are propagated (see ``_CONFIG_SYNC_KEYS``). The safety-critical
      ``exploit.permission`` / ``exploit.attack_mode`` are NEVER touched here.
    Returns whether config.yaml was also updated.
    """
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(
        json.dumps(settings, indent=2, default=str),
        encoding="utf-8",
    )
    return _sync_config_keys(settings)


class SettingsScreen(Screen):
    """Configure TUI and application settings."""

    BINDINGS = [
        Binding("s", "save", "Save"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        settings = _load_settings()
        model_options, model_value = _model_select_options(str(settings.get("default_model", "glm")))

        with VerticalScroll(id="settings-body"):
            # General
            yield Static("\n[bold]GENERAL[/]")
            yield Label("Ollama Host URL:")
            yield Input(value=settings.get("ollama_host", "http://localhost:11434"), id="set-ollama-host")
            yield Label("Default Model Alias (label, context window):")
            yield Select(
                model_options,
                id="set-default-model",
                value=model_value,
            )
            yield Label("Workspace Directory:")
            yield Input(value=settings.get("workspace_dir", "research_workspace"), id="set-workspace-dir")
            yield Label("Auto-refresh (seconds):")
            yield Input(value=str(settings.get("auto_refresh", 5)), id="set-refresh")

            # Model spending
            yield Static("\n[bold]MODEL SPEND[/]")
            yield Label("Peer-model consultation:")
            yield Switch(value=settings.get("multi_model_consult", False), id="set-multi-model")

            # Safety
            yield Static("\n[bold]SAFETY[/]")
            yield Label("Default Risk Profile:")
            yield Select(
                [("Low-noise (safe)", "low_noise_non_destructive"),
                 ("Standard (authorized)", "standard_authorized"),
                 ("High (owned infra)", "high_authorized_testing")],
                id="set-risk-default",
                value=settings.get("default_risk", "standard_authorized"),
            )

            # Stealth
            yield Static("\n[bold]STEALTH DEFAULTS[/]")
            yield Label("Rotate User-Agent:")
            yield Switch(value=settings.get("rotate_ua", False), id="set-rotate-ua")
            yield Label("DNS-over-HTTPS:")
            yield Switch(value=settings.get("doh", False), id="set-doh")

            # Theme
            yield Static("\n[bold]THEME[/]")
            yield Label("Use Unicode icons:")
            yield Switch(value=settings.get("unicode_icons", True), id="set-unicode")

        with Horizontal(id="settings-actions-container"):
            yield Button("Save (Ctrl+S)", id="btn-save", variant="primary")
            yield Button("Reset Defaults", id="btn-reset")
        yield HelpFooter(id="settings-footer")

    def on_mount(self) -> None:
        self.query_one("#settings-footer", HelpFooter).show_context("s Save", "Esc Back")

    @on(Button.Pressed, "#btn-save")
    def action_save(self) -> None:
        settings = _load_settings()

        # Collect values from widgets. On a read failure (widget missing) we notify
        # and abort BEFORE _save_settings so we never persist a half-read config.
        try:
            settings["ollama_host"] = self.query_one("#set-ollama-host", Input).value
        except Exception:
            self.notify("Could not read Ollama Host", severity="error")
            return
        try:
            settings["default_model"] = self.query_one("#set-default-model", Select).value
        except Exception:
            self.notify("Could not read Default Model", severity="error")
            return
        try:
            settings["workspace_dir"] = self.query_one("#set-workspace-dir", Input).value
        except Exception:
            self.notify("Could not read Workspace Directory", severity="error")
            return
        try:
            refresh_raw = self.query_one("#set-refresh", Input).value or "5"
        except Exception:
            self.notify("Could not read Auto-refresh", severity="error")
            return
        try:
            settings["auto_refresh"] = int(refresh_raw)
        except ValueError:
            # Non-numeric auto-refresh: warn and fall back to 5 instead of silent reset.
            settings["auto_refresh"] = 5
            self.notify("Auto-refresh must be a number; using 5", severity="warning")
        try:
            settings["default_risk"] = self.query_one("#set-risk-default", Select).value
        except Exception:
            self.notify("Could not read Default Risk Profile", severity="error")
            return
        try:
            settings["rotate_ua"] = self.query_one("#set-rotate-ua", Switch).value
        except Exception:
            self.notify("Could not read Rotate User-Agent", severity="error")
            return
        try:
            settings["doh"] = self.query_one("#set-doh", Switch).value
        except Exception:
            self.notify("Could not read DNS-over-HTTPS", severity="error")
            return
        try:
            settings["multi_model_consult"] = self.query_one("#set-multi-model", Switch).value
        except Exception:
            self.notify("Could not read Peer-model consultation", severity="error")
            return
        try:
            unicode_val = self.query_one("#set-unicode", Switch).value
            settings["unicode_icons"] = unicode_val
            set_icon_mode(unicode_val)
        except Exception:
            self.notify("Could not read Unicode icons", severity="error")
            return

        try:
            synced = _save_settings(settings)
        except OSError:
            self.notify("Could not save settings.", severity="error")
            return
        msg = "Settings saved to research_workspace/settings.json"
        if synced:
            msg += " and config.yaml"
        self.notify(msg, severity="information")

    @on(Button.Pressed, "#btn-reset")
    def action_reset(self) -> None:
        defaults = {
            "unicode_icons": True,
            "ollama_host": "http://localhost:11434",
            "default_model": "glm",
            "rotate_ua": False,
            "doh": False,
            "default_risk": "standard_authorized",
            "workspace_dir": "research_workspace",
            "auto_refresh": 5,
            "multi_model_consult": False,
        }
        try:
            _save_settings(defaults)
        except OSError:
            self.notify("Could not save settings.", severity="error")
            return

        # Reset widgets. A reset failure is non-fatal (save already succeeded);
        # notify and continue resetting the remaining widgets rather than swallow.
        try:
            self.query_one("#set-ollama-host", Input).value = defaults["ollama_host"]
        except Exception:
            self.notify("Could not reset Ollama Host", severity="warning")
        try:
            self.query_one("#set-default-model", Select).value = defaults["default_model"]
        except Exception:
            self.notify("Could not reset Default Model", severity="warning")
        try:
            self.query_one("#set-workspace-dir", Input).value = defaults["workspace_dir"]
        except Exception:
            self.notify("Could not reset Workspace Directory", severity="warning")
        try:
            self.query_one("#set-refresh", Input).value = str(defaults["auto_refresh"])
        except Exception:
            self.notify("Could not reset Auto-refresh", severity="warning")
        try:
            self.query_one("#set-risk-default", Select).value = defaults["default_risk"]
        except Exception:
            self.notify("Could not reset Default Risk Profile", severity="warning")
        try:
            self.query_one("#set-rotate-ua", Switch).value = defaults["rotate_ua"]
        except Exception:
            self.notify("Could not reset Rotate User-Agent", severity="warning")
        try:
            self.query_one("#set-doh", Switch).value = defaults["doh"]
        except Exception:
            self.notify("Could not reset DNS-over-HTTPS", severity="warning")
        try:
            self.query_one("#set-multi-model", Switch).value = defaults["multi_model_consult"]
        except Exception:
            self.notify("Could not reset Peer-model consultation", severity="warning")
        try:
            self.query_one("#set-unicode", Switch).value = defaults["unicode_icons"]
            set_icon_mode(True)
        except Exception:
            self.notify("Could not reset Unicode icons", severity="warning")

        self.notify("Settings reset to defaults.")
