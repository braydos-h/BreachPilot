"""Shared nmap privilege-handling helpers.

Extracted from ``mcp_server.py`` so the *defensive* MCP server and the
exploit recon pipeline (``tools/recon_pipeline.py``) apply the SAME
unprivileged-downgrade behaviour. Previously only the defensive server
downgraded root-requiring flags (``-O``/``-sS``/...); the recon pipeline
hardcoded ``-sS``/``-O`` and failed on a non-root host, retrying the
identical failing command three times.

These helpers are also reused (re-exported) by ``mcp_server.py`` so
existing imports ``from mcp_server import _downgrade_unprivileged_args``
keep working.
"""

from __future__ import annotations

import os
import re

# nmap flags that require root / CAP_NET_RAW on Linux. Connect-scan + service
# detection do not; SYN/Xmas/Null/FIN/ACK/Maimon + OS detection (``-O``) do.
_NMAP_ROOT_FLAGS: set[str] = {"-O", "-sS", "-sX", "-sN", "-sF", "-sA", "-sM"}


def _is_privileged() -> bool:
    """True if the process may use raw-packet nmap scans.

    On POSIX this means euid 0 (root). Windows has no root concept, so nmap
    on Windows does its own socket handling and is treated as privileged.
    """
    if os.name == "nt":
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def _downgrade_unprivileged_args(args: list[str]) -> tuple[list[str], str]:
    """Return (args, note). Strip root-requiring nmap flags when unprivileged.

    If ``args`` contains a SYN scan flag, replace it with ``-sT`` (TCP connect
    scan, no root needed) so port coverage is preserved. ``-O`` and the other
    raw-packet scan types are simply removed. The returned note explains what
    was downgraded so the caller can surface it to the operator.
    """
    out: list[str] = []
    removed: list[str] = []
    has_syn = False
    for tok in args:
        if tok in _NMAP_ROOT_FLAGS:
            removed.append(tok)
            if tok == "-sS":
                has_syn = True
        else:
            out.append(tok)
    if not removed:
        return args, ""
    if has_syn:
        out.append("-sT")
    note = (
        "nmap: removed root-requiring flags "
        + ",".join(removed)
        + " (needs root). Rerun as root or set nmap.sudo: true in config.yaml "
        "to enable OS/SYN scans. SYN scan was replaced with -sT (connect scan)."
    )
    return out, note


def apply_nmap_privilege(
    argv: list[str], *, sudo: bool, priv_fallback: bool
) -> tuple[list[str], str]:
    """Apply sudo-prefix + unprivileged downgrade to a full nmap argv.

    ``argv[0]`` is the nmap binary (e.g. ``nmap`` or a configured path); the
    remaining tokens are the flags/target. Returns ``(effective_argv, note)``.

    - Privileged (root / Windows): no change.
    - Unprivileged + ``sudo``: prepend ``sudo -n`` (non-interactive; fails
      fast instead of hanging on a password prompt). No downgrade — sudo
      gives root.
    - Unprivileged + ``priv_fallback``: strip root-requiring flags, replacing
      ``-sS`` with ``-sT``. The note describes the downgrade.
    - Unprivileged, neither: return argv unchanged (the scan will fail with a
      privilege error; the caller may then retry once with ``priv_fallback=True``).
    """
    if _is_privileged():
        return list(argv), ""
    binary = argv[0]
    rest = list(argv[1:])
    use_sudo = sudo and os.name != "nt"
    if use_sudo:
        return ["sudo", "-n", binary, *rest], ""
    if priv_fallback and os.name != "nt":
        downgraded, note = _downgrade_unprivileged_args(rest)
        return [binary, *downgraded], note
    return list(argv), ""


_PRIV_ERROR_RE = re.compile(
    r"requires root|raw socket|permission denied|cap_net_raw|must be run as root|"
    r"you requested a scan type which requires root",
    re.IGNORECASE,
)


def is_privilege_error(stderr: str) -> bool:
    """True if a scan's stderr indicates a root/privilege failure.

    Such failures are identical across retries, so ``run_command`` uses this
    to break out of its retry loop early and let the caller downgrade the argv
    (``-sS`` -> ``-sT``) and retry once with the corrected command.
    """
    return bool(_PRIV_ERROR_RE.search(stderr or ""))
