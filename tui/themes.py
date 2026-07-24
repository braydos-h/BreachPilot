"""Theme constants for the TUI.

Provides color constants, icon constants with ASCII fallbacks,
and status-to-color mappings used across all screens.
"""

from __future__ import annotations

# ── Color constants (Textual CSS-compatible) ───────────────────────────────

COLORS = {
    "safe": "#00ff87",           # Bright green — safe/allowed/complete
    "warning": "#ffaa00",        # Amber — caution/needs attention
    "danger": "#ff4444",         # Red — blocked/error/high risk
    "info": "#4488ff",           # Blue — informational
    "accent": "#cc66ff",         # Purple — active selection/highlight
    "muted": "#666666",          # Gray — dimmed/inactive
    "success": "#00cc66",        # Green
    "pending": "#ffffff",        # White
    "running": "#ffaa00",        # Yellow
    "blocked": "#ff4444",        # Red
    "failed": "#ff6666",         # Light red
    "complete": "#22aa55",       # Dim green
    "critical": "#ff2222",       # Bright red
    "high": "#ff8844",           # Orange
    "medium": "#ffcc00",         # Gold
    "low": "#88cc00",            # Olive
    "info_label": "#4488ff",     # Blue
}

# ── Status-to-class mapping ────────────────────────────────────────────────

TASK_ROW_CLASSES = {
    "pending": "task-row-pending",
    "running": "task-row-running",
    "blocked": "task-row-blocked",
    "complete": "task-row-complete",
    "failed": "task-row-failed",
    "needs_approval": "task-row-needs-approval",
}

FINDING_ROW_CLASSES = {
    "candidate": "finding-row-candidate",
    "needs_validation": "finding-row-needs-validation",
    "validated": "finding-row-validated",
    "report_ready": "finding-row-report-ready",
    "rejected": "finding-row-rejected",
    "duplicate_suspected": "finding-row-duplicate",
}

# ── Icons with ASCII fallback ──────────────────────────────────────────────

_USE_UNICODE = True

def set_icon_mode(unicode_mode: bool) -> None:
    global _USE_UNICODE
    _USE_UNICODE = unicode_mode


def icon(key: str) -> str:
    icons_unicode = {
        "safe": "✓",
        "warning": "⚠",
        "blocked": "⛔",
        "recon": "🔍",
        "memory": "🧠",
        "task": "📋",
        "evidence": "📁",
        "finding": "🐞",
        "report": "📝",
        "graph": "🗺 ",
        "log": "📜",
        "settings": "⚙ ",
        "dashboard": "📊",
        "scope": "🔒",
        "target": "🎯",
        "execute": "▶",
        "back": "←",
        "star": "★",
        "check": "✓",
        "cross": "✗",
        "circle": "○",
        "question": "?",
        "dup": "≃",
        "up": "↑",
        "down": "↓",
        "left": "←",
        "right": "→",
        "nav": "↕ ",
    }
    icons_ascii = {
        "safe": "+",
        "warning": "!",
        "blocked": "X",
        "recon": "R",
        "memory": "M",
        "task": "T",
        "evidence": "E",
        "finding": "F",
        "report": "R",
        "graph": "G",
        "log": "L",
        "settings": "S",
        "dashboard": "D",
        "scope": "S",
        "target": "T",
        "execute": ">",
        "back": "<-",
        "star": "*",
        "check": "+",
        "cross": "X",
        "circle": "o",
        "question": "?",
        "dup": "~",
        "up": "^",
        "down": "v",
        "left": "<",
        "right": ">",
        "nav": "^v",
    }
    source = icons_unicode if _USE_UNICODE else icons_ascii
    return source.get(key, key)


# ── Status mapping ─────────────────────────────────────────────────────────

STATUS_ICONS = {
    "report_ready": icon("star"),
    "validated": icon("check"),
    "candidate": icon("circle"),
    "needs_validation": icon("question"),
    "rejected": icon("cross"),
    "duplicate_suspected": icon("dup"),
    "running": icon("warning"),
    "complete": icon("check"),
    "failed": icon("cross"),
    "blocked": icon("blocked"),
    "idle": icon("circle"),
}

RISK_PROFILE_COLORS = {
    "low_noise_non_destructive": COLORS["safe"],
    "standard_authorized": COLORS["warning"],
    "high_authorized_testing": COLORS["danger"],
}

RISK_PROFILE_LABELS = {
    "low_noise_non_destructive": "SAFE",
    "standard_authorized": "STANDARD",
    "high_authorized_testing": "HIGH",
}
