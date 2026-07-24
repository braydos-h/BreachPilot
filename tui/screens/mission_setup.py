"""Mission setup wizard — 9-step interactive form for creating missions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button, Checkbox, Footer, Header, Input, Label, RadioButton, RadioSet,
    Select, Static, Switch, TextArea,
)
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter

MISSION_DEFAULT_OBJECTIVE = (
    "Identify valid, in-scope, non-destructive, reproducible "
    "security issues with clear evidence."
)

FORBIDDEN_OPTIONS = [
    ("denial_of_service", True),
    ("destructive_exploit", True),
    ("credential_theft", True),
    ("social_engineering", True),
    ("physical_attack", True),
    ("persistence", True),
    ("malware", True),
    ("uncontrolled_fuzzing", True),
    ("data_exfiltration", False),
]

RISK_PROFILES = [
    ("low_noise_non_destructive", "Low-Noise (safe) — Recon + Analysis only"),
    ("standard_authorized", "Standard — Authorized bug bounty (test, validate)"),
    ("high_authorized_testing", "High — Full exploitation on owned infra"),
]

TESTING_MODES = [
    ("recon", True),
    ("analysis", True),
    ("test", False),
    ("validate", False),
    ("exploit", False),
    ("report", True),
]


class MissionSetupScreen(Screen):
    """Step-by-step wizard to create a new mission."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self) -> None:
        # Instance state, NOT class attributes. Previously `_step`/`_values` were
        # class-level, so two MissionSetupScreen instances (or a re-mounted one)
        # shared the same dict/counter -- wizard state bled across sessions.
        super().__init__()
        self._step = 0
        self._values: dict = {}

    def compose(self) -> ComposeResult:
        yield Static("", id="wiz-error")
        with Horizontal(id="wiz-layout"):
            # Step sidebar
            with Vertical(id="wiz-steps"):
                yield Static("[bold]STEPS[/]", id="wiz-step-title")
                yield Static("", id="wiz-step-list")
            # Main content
            with VerticalScroll(id="wiz-content"):
                yield Static("", id="wiz-content-area")
        # Navigation
        with Horizontal(id="wiz-nav"):
            yield Button("<- Back", id="wiz-back", disabled=True)
            yield Static("", id="wiz-step-indicator")
            yield Button("Next ->", id="wiz-next", variant="primary")
            yield Button("Create Mission", id="wiz-create", variant="success")
        yield HelpFooter(id="wiz-footer")

    def on_mount(self) -> None:
        self._build_step_list()
        self._show_step(0)

    def _build_step_list(self) -> None:
        steps = [
            "1. Program Info",
            "2. Objective",
            "3. Allowed Assets",
            "4. Disallowed Assets",
            "5. Forbidden Actions",
            "6. Rate Limits",
            "7. Risk Profile",
            "8. Testing Modes",
            "9. Accounts",
            "10. Review & Create",
        ]
        lines = []
        for i, s in enumerate(steps):
            if i == self._step:
                lines.append(f"[bold reverse]  {s}  [/]")
            else:
                lines.append(f"  [dim]{s}[/]")
        self.query_one("#wiz-step-list", Static).update("\n".join(lines))

    def _show_step(self, step: int) -> None:
        self._step = step
        self._build_step_list()

        area = self.query_one("#wiz-content-area", Static)
        # Clear previous step's widgets
        for child in list(area.children):
            child.remove()
        self.query_one("#wiz-content").scroll_home()

        if step == 0:
            self._step_program_info(area)
        elif step == 1:
            self._step_objective(area)
        elif step == 2:
            self._step_allowed(area)
        elif step == 3:
            self._step_disallowed(area)
        elif step == 4:
            self._step_forbidden(area)
        elif step == 5:
            self._step_rate_limits(area)
        elif step == 6:
            self._step_risk(area)
        elif step == 7:
            self._step_testing_modes(area)
        elif step == 8:
            self._step_accounts(area)
        elif step == 9:
            self._step_review(area)

        self.query_one("#wiz-step-indicator", Static).update(
            f"Step {step+1}/10"
        )
        self.query_one("#wiz-back", Button).disabled = step == 0
        self.query_one("#wiz-next", Button).display = step < 9
        self.query_one("#wiz-create", Button).display = step == 9

        self.query_one("#wiz-footer", HelpFooter).show_context(
            "Enter/Next Continue", "Esc Cancel"
        )

    def _step_program_info(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Program Information[/]\n\n"
            "Program Name:\n  > Type your program name below.\n"
        ))
        area.mount(Input(
            value=self._values.get("name", ""),
            placeholder="e.g., Acme Corp Bug Bounty",
            id="wiz-input-name",
        ))

    def _step_objective(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Objective[/]\n\n"
            f"Default: {MISSION_DEFAULT_OBJECTIVE}\n\n"
            "You can customize or leave as-is.\n"
        ))
        area.mount(Input(
            value=self._values.get("objective", MISSION_DEFAULT_OBJECTIVE),
            placeholder=MISSION_DEFAULT_OBJECTIVE,
            id="wiz-input-objective",
        ))

    def _step_allowed(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Allowed Assets[/]\n\n"
            "Enter each asset on a new line:\n"
            "  example.com\n"
            "  *.example.com (wildcard)\n"
            "  192.168.1.1 (IP)\n"
            "  10.0.0.0/24 (CIDR)\n"
        ))
        area.mount(TextArea(
            text="\n".join(self._values.get("allowed", ["example.com", "*.example.com"])),
            id="wiz-input-allowed",
        ))

    def _step_disallowed(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Disallowed Assets[/]\n\n"
            "Enter exclusions (one per line):\n"
            "  payments.example.com\n"
            "  192.168.1.254 (gateway)\n"
        ))
        area.mount(TextArea(
            text="\n".join(self._values.get("denied", [])),
            id="wiz-input-denied",
        ))

    def _step_forbidden(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Forbidden Actions[/]\n\n"
            "Check actions to FORBID:\n"
        ))
        for action, default_checked in FORBIDDEN_OPTIONS:
            current = self._values.get("forbidden", [])
            checked = action in current if current else default_checked
            area.mount(Checkbox(
                label=action.replace("_", " ").title(),
                value=checked,
                id=f"wiz-forbidden-{action}",
            ))

    def _step_rate_limits(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Rate Limits[/]\n\n"
            "Default requests/sec:\n"
        ))
        area.mount(Input(
            value=str(self._values.get("rate_limits", {}).get("default_requests_per_second", 2)),
            id="wiz-input-rate",
        ))

    def _step_risk(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Risk Profile[/]\n\n"
        ))
        current_risk = self._values.get("risk", "standard_authorized")
        area.mount(Select(
            [(label, value) for value, label in RISK_PROFILES],
            id="wiz-select-risk",
            value=current_risk if current_risk in dict(RISK_PROFILES) else "standard_authorized",
        ))

    def _step_testing_modes(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Testing Modes[/]\n\n"
        ))
        current_modes = self._values.get("testing_modes", ["recon", "analysis", "report"])
        for mode, default_checked in TESTING_MODES:
            area.mount(Checkbox(
                label=mode.replace("_", " ").title(),
                value=mode in current_modes,
                id=f"wiz-mode-{mode}",
            ))

    def _step_accounts(self, area: Static) -> None:
        area.mount(Static(
            "\n[bold]Accounts[/]\n\n"
            "Optional — provide test credentials (one per line, format: role:username:password)\n"
            "Leave empty for unauthenticated testing.\n"
        ))
        area.mount(TextArea(
            text="\n".join(self._values.get("accounts", [])),
            id="wiz-input-accounts",
        ))

    def _step_review(self, area: Static) -> None:
        lines = [
            "\n[bold green]REVIEW YOUR MISSION[/]\n",
            f"[bold]Program:[/] {self._values.get('name', '(not set)')}",
            f"[bold]Objective:[/] {self._values.get('objective', MISSION_DEFAULT_OBJECTIVE)}",
            f"[bold]Risk:[/] {self._values.get('risk', 'low_noise_non_destructive')}",
            f"[bold]Allowed:[/] {', '.join(self._values.get('allowed', [])) or '(none)'}",
            f"[bold]Denied:[/] {', '.join(self._values.get('denied', [])) or '(none)'}",
            f"[bold]Forbidden:[/] {', '.join(self._values.get('forbidden', []))}",
            f"[bold]Testing:[/] {', '.join(self._values.get('testing_modes', ['recon','analysis','report']))}",
            "",
            "[bold green]Press 'Create Mission' to save.[/]",
        ]
        area.update("\n".join(lines))

    @on(Button.Pressed, "#wiz-next")
    def _next_step(self) -> None:
        self._collect_current()
        if self._step < 9:
            self._show_step(self._step + 1)

    @on(Button.Pressed, "#wiz-back")
    def _prev_step(self) -> None:
        if self._step > 0:
            self._show_step(self._step - 1)

    @on(Button.Pressed, "#wiz-create")
    def _create(self) -> None:
        self._collect_current()

        # ── Validation ────────────────────────────────────────────────
        errors = []
        name = (self._values.get("name") or "").strip()
        if not name:
            errors.append("Program name cannot be empty.")
        allowed = self._values.get("allowed", [])
        if not allowed:
            errors.append("At least one allowed asset is required.")
        risk = self._values.get("risk", "")
        if not risk:
            errors.append("Risk profile must be selected.")

        if errors:
            for err in errors:
                self.notify(err, severity="error")
            return

        svc = self._get_services()

        # Normalize risk profile value
        risk_raw = self._values.get("risk", "standard_authorized")
        if "low" in risk_raw.lower():
            risk = "low_noise_non_destructive"
        elif "high" in risk_raw.lower():
            risk = "high_authorized_testing"
        else:
            risk = "standard_authorized"

        config = {
            "program_name": name,
            "objective": self._values.get("objective", MISSION_DEFAULT_OBJECTIVE),
            "risk_profile": risk,
            "allowed_assets": allowed,
            "disallowed_assets": self._values.get("denied", []),
            "forbidden_actions": self._values.get("forbidden", [
                "denial_of_service", "destructive_exploit", "credential_theft",
                "social_engineering", "physical_attack", "persistence", "malware",
                "uncontrolled_fuzzing",
            ]),
            "testing_modes": self._values.get("testing_modes", ["recon", "analysis", "report"]),
            "rate_limits": self._values.get("rate_limits", {
                "default_requests_per_second": 2,
                "max_concurrent_requests": 3,
            }),
            "accounts": self._values.get("accounts", []),
            "notes": self._values.get("notes", ""),
        }

        try:
            mission = svc.create_mission(config)
            svc.reload()
            self.notify(
                f"Mission '{mission.program_name}' created! ID: {mission.mission_id}",
                severity="information",
            )
            # Auto-redirect to Dashboard
            self.dismiss()
            from tui.screens.dashboard import DashboardScreen
            self.app.switch_screen(DashboardScreen())
        except ValueError as exc:
            self.notify(f"Validation error: {exc}", severity="error")
        except Exception as exc:
            self.notify(f"Failed to create mission: {exc}", severity="error")

    def _collect_current(self) -> None:
        """Collect values from the current step's input widgets."""
        if self._step == 0:
            try:
                inp = self.query_one("#wiz-input-name", Input)
                self._values["name"] = inp.value.strip()
            except Exception:
                self._values.setdefault("name", "Unnamed Program")
        elif self._step == 1:
            try:
                inp = self.query_one("#wiz-input-objective", Input)
                self._values["objective"] = inp.value.strip() or MISSION_DEFAULT_OBJECTIVE
            except Exception:
                self._values.setdefault("objective", MISSION_DEFAULT_OBJECTIVE)
        elif self._step == 2:
            try:
                ta = self.query_one("#wiz-input-allowed", TextArea)
                lines = [l.strip() for l in ta.text.splitlines() if l.strip()]
                # Preserve the list as-is (even when empty) so _create's validation
                # can surface "At least one allowed asset is required." rather than
                # silently inserting a placeholder asset.
                self._values["allowed"] = lines
            except Exception:
                self._values["allowed"] = []
        elif self._step == 3:
            try:
                ta = self.query_one("#wiz-input-denied", TextArea)
                lines = [l.strip() for l in ta.text.splitlines() if l.strip()]
                self._values["denied"] = lines
            except Exception:
                self._values.setdefault("denied", [])
        elif self._step == 4:
            forbidden = []
            for action, _ in FORBIDDEN_OPTIONS:
                try:
                    cb = self.query_one(f"#wiz-forbidden-{action}", Checkbox)
                    if cb.value:
                        forbidden.append(action)
                except Exception:
                    pass
            self._values["forbidden"] = forbidden
        elif self._step == 5:
            try:
                inp = self.query_one("#wiz-input-rate", Input)
                rate = int(inp.value.strip() or "2")
            except (ValueError, Exception):
                rate = 2
            self._values["rate_limits"] = {"default_requests_per_second": rate, "max_concurrent_requests": 3}
        elif self._step == 6:
            try:
                sel = self.query_one("#wiz-select-risk", Select)
                self._values["risk"] = sel.value
            except Exception:
                self._values.setdefault("risk", "standard_authorized")
        elif self._step == 7:
            modes = []
            for mode, _ in TESTING_MODES:
                try:
                    cb = self.query_one(f"#wiz-mode-{mode}", Checkbox)
                    if cb.value:
                        modes.append(mode)
                except Exception:
                    pass
            self._values["testing_modes"] = modes if modes else ["recon", "analysis", "report"]
        elif self._step == 8:
            try:
                ta = self.query_one("#wiz-input-accounts", TextArea)
                lines = [l.strip() for l in ta.text.splitlines() if l.strip()]
                self._values["accounts"] = lines
            except Exception:
                self._values.setdefault("accounts", [])

    def action_cancel(self) -> None:
        self.dismiss()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
