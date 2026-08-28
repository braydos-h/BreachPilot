"""Attack-state enum for the kill-chain state machine (design §killchain).

States form a small lattice the agent climbs: ``discovered`` → ``reachable`` →
``service_access`` → ``creds_in_hand`` → ``shell_as_user`` → ``shell_as_root``,
with lateral/domain branches (``pivot_reachable``, ``domain_creds``, ``da``).

There is no per-target fixed list of applicable states — applicability is
edge-driven: the states that appear in the registered edge registry
(:data:`tools.killchain.edges.EDGES`) are the ones a target can move between.
"""

from __future__ import annotations

from enum import Enum

_ALIASES = {
    "discovered": "discovered",
    "discover": "discovered",
    "reachable": "reachable",
    "network_reachable": "reachable",
    "service_access": "service_access",
    "service": "service_access",
    "creds_in_hand": "creds_in_hand",
    "credentials_in_hand": "creds_in_hand",
    "creds": "creds_in_hand",
    "shell_as_user": "shell_as_user",
    "user_shell": "shell_as_user",
    "shell": "shell_as_user",
    "shell_as_root": "shell_as_root",
    "root_shell": "shell_as_root",
    "root": "shell_as_root",
    "pivot_reachable": "pivot_reachable",
    "pivot": "pivot_reachable",
    "domain_creds": "domain_creds",
    "domain_credentials": "domain_creds",
    "da": "da",
    "domain_admin": "da",
}


class AttackState(str, Enum):
    """Kill-chain states. ``str``-based so values serialize cleanly to JSON."""

    DISCOVERED = "discovered"
    REACHABLE = "reachable"
    SERVICE_ACCESS = "service_access"
    CREDS_IN_HAND = "creds_in_hand"
    SHELL_AS_USER = "shell_as_user"
    SHELL_AS_ROOT = "shell_as_root"
    PIVOT_REACHABLE = "pivot_reachable"
    DOMAIN_CREDS = "domain_creds"
    DA = "da"

    @classmethod
    def parse(cls, value: str) -> "AttackState":
        """Tolerant parse: case/alias-insensitive; raises ``ValueError`` when unknown."""
        key = str(value or "").strip().lower()
        if key in _ALIASES:
            return cls(_ALIASES[key])
        raise ValueError(
            f"unknown attack state {value!r} (valid: {', '.join(s.value for s in cls)})"
        )