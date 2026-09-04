"""Closed artifact vocabulary for attack-module capability composition.

``requires``/``produces`` strings on :class:`AttackModule` must come from
``ARTIFACT_VOCAB``. The old ``_artifact_present`` treated any unknown kind
as present ("so a typo never hides the module"), which silently passed
gating on typos and made producer/consumer mismatches invisible. Unknown
kinds are now absent (fail closed) and flagged by the contract test.
"""

from __future__ import annotations

from typing import Any

# Canonical artifact kinds. Aliases map onto these (e.g. a module declaring
# ``creds`` means ``credentials``).
ARTIFACT_VOCAB: frozenset[str] = frozenset(
    {
        "credentials",
        "hash_artifact",
        "user_list",
        "foothold",
        "shell",
        "webshell",
        "session",
        "admin_priv",
        "high_priv",
        "persistence",
        "signing_posture",
        "git_config_leak",
        "vuln_confirmed",
        "lpe_candidates",
        "k8s_sa_token",
        "web_tech",
        "auth_scheme",
    }
)

_ALIASES: dict[str, str] = {
    "creds": "credentials",
    "password": "credentials",
    "hash": "hash_artifact",
    "root_priv": "admin_priv",
    "system_priv": "admin_priv",
}

_FOOTHOLD_KINDS = {"foothold", "shell", "session"}
_PRIV_KINDS = {"admin_priv", "high_priv"}

# Artifacts that are terminal findings (no consumer expected).
# high_priv: escalation outcome, end of chain (admin_priv is the plannable
# currency; high_priv marks cloud/container vectors already realized).
# webshell: terminal access — WebShellUpload co-produces foothold, which is
# what chains consume.
TERMINAL_ARTIFACTS: frozenset[str] = frozenset({"persistence", "vuln_confirmed", "high_priv", "webshell"})


def normalize(kind: str) -> str:
    """Lowercase + alias-resolve an artifact kind. Unknown kinds pass through
    unchanged (so the contract test can flag them as non-vocab)."""
    k = (kind or "").strip().lower()
    return _ALIASES.get(k, k)


def is_known(kind: str) -> bool:
    """True when ``kind`` is in the closed vocabulary (after aliasing)."""
    return normalize(kind) in ARTIFACT_VOCAB


def unknown_kinds(kinds: list[str]) -> list[str]:
    """Return entries of ``kinds`` outside the closed vocabulary."""
    return [k for k in kinds if not is_known(k)]


def is_satisfied(kind: str, ctx: Any) -> bool:
    """Best-effort prerequisite check: is artifact ``kind`` available in ctx?

    Closed-world: unknown kinds are NOT satisfiable (fail closed). Known
    kinds resolve against credentials / sessions / privilege level.
    """
    k = normalize(kind)
    if k not in ARTIFACT_VOCAB:
        return False
    if k == "credentials":
        return bool(getattr(ctx, "credentials", None))
    if k == "hash_artifact":
        creds = getattr(ctx, "credentials", None) or []
        if creds:
            return True
        findings = getattr(ctx, "findings", None) or []
        return any("hash" in str(f).lower() for f in findings)
    if k in _FOOTHOLD_KINDS or k == "webshell":
        return bool(getattr(ctx, "access_achieved", False) or getattr(ctx, "sessions", None))
    if k in _PRIV_KINDS:
        return str(getattr(ctx, "privilege_level", "") or "").lower() in {
            "admin",
            "administrator",
            "system",
            "root",
            "high",
        }
    if k == "user_list":
        creds = getattr(ctx, "credentials", None) or []
        if any("user" in str(c).lower() for c in creds):
            return True
        findings = getattr(ctx, "findings", None) or []
        return any("user" in str(f).lower() for f in findings)
    # State-backed artifacts with no ctx field yet (signing_posture,
    # git_config_leak, vuln_confirmed, lpe_candidates, k8s_sa_token,
    # web_tech, auth_scheme): satisfiable only via explicit findings refs.
    findings = getattr(ctx, "findings", None) or []
    return any(k in str(f).lower() for f in findings)
