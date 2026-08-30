"""OPSEC manager for the lab-build authorized-pentest agent.

OPSEC here means **hardening the agent's own behavior** -- pacing between
actions, User-Agent rotation, DNS-over-HTTPS resolution, quiet-command
blocking, and noise scoring / low-noise alternative suggestions -- plus
detection-coverage reporting. It is NOT active evasion of the target's
defenses: no log clearing, no timestomping, no EDR/SIEM defeat, no hiding
from the operator. The audit trail (``exploit_audit.jsonl``) is
append-only/tamper-evident and is never touched by this module.

Design constraints (matched to the rest of the codebase):

* Pure stdlib only. ``random`` and ``time`` are imported **lazily** so that
  importing this module at collection time has no side effects and tests can
  run with no real network, no real sleep.
* Any network / DNS / HTTP / time / random behavior is injectable via the
  constructor (``rng``, ``fetch_fn``, ``rate_limiter``, ``sleep_fn``) so the
  test suite is fully deterministic and hermetic.
* Detection / scoring helpers are read-only / planning only and never
  execute anything.
"""

from __future__ import annotations

import asyncio
import json
import socket
import urllib.request
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Sequence

# ---------------------------------------------------------------------------
# Aggression -> pacing factor
# ---------------------------------------------------------------------------

AGGRESSION_FACTOR: dict[str, float] = {
    "stealth": 2.0,
    "normal": 1.0,
    "aggressive": 0.5,
    "maximum": 0.0,
}
"""Multiplier applied to ``OpsecProfile.min_gap_seconds`` per aggression level.

``maximum`` collapses the base gap to 0 (no pacing); ``stealth`` doubles it.
Unknown aggression strings fall back to the ``normal`` factor (1.0)."""


# ---------------------------------------------------------------------------
# OpsecProfile
# ---------------------------------------------------------------------------


@dataclass
class OpsecProfile:
    """Static OPSEC configuration loaded from the ``opsec`` config block.

    All fields default to "off" so a missing/partial config never silently
    enables aggressive behavior. ``from_config`` is tolerant of missing keys.
    """

    enabled: bool = False
    ua_rotation: bool = False
    doh: bool = False
    doh_provider: str = "cloudflare"  # "cloudflare" | "google"
    min_gap_seconds: float = 0.0  # pacing: base min gap between actions
    jitter_seconds: float = 0.0  # +/- random jitter added to the gap
    rate_per_minute: int = 0  # 0 = no token-bucket cap
    quiet_command_patterns: tuple[str, ...] = ()  # substrings to refuse when enabled
    noise_budget: int = 0  # max noisy commands allowed (0 = unlimited)
    # Target-aware OPSEC (Phase 6.2+). When ``local_targets_off`` is true (the
    # default), resolving the profile against a private/local target IP yields a
    # fully-disabled profile -- the operator owns the box and wants the AI to
    # move freely without pacing/UA-rotation/quiet-blocking. A public-routable
    # target keeps the configured posture. ``local_cidrs`` lets the operator
    # mark extra ranges (e.g. a lab CIDR) as local. ``public_autonomy`` is an
    # explicit assertion that for public targets the AI chooses its own attacks
    # (already true in full_access mode); it is documentary + available to prompt
    # builders, not a runtime gate.
    local_targets_off: bool = True
    local_cidrs: tuple[str, ...] = ()
    public_autonomy: bool = True

    @classmethod
    def from_config(cls, cfg: dict) -> "OpsecProfile":
        """Build an :class:`OpsecProfile` from a config dict.

        Reads the ``opsec`` sub-block of ``cfg``. Tolerant of a missing or
        empty ``opsec`` block and of any missing individual keys; every field
        keeps its dataclass default when unset.
        """
        block = (cfg or {}).get("opsec", {}) or {}
        return cls(
            enabled=bool(block.get("enabled", False)),
            ua_rotation=bool(block.get("ua_rotation", False)),
            doh=bool(block.get("doh", False)),
            doh_provider=str(block.get("doh_provider", "cloudflare")),
            min_gap_seconds=float(block.get("min_gap_seconds", 0.0)),
            jitter_seconds=float(block.get("jitter_seconds", 0.0)),
            rate_per_minute=int(block.get("rate_per_minute", 0)),
            quiet_command_patterns=tuple(block.get("quiet_command_patterns", []) or []),
            noise_budget=int(block.get("noise_budget", 0)),
            local_targets_off=bool(block.get("local_targets_off", True)),
            local_cidrs=tuple(block.get("local_cidrs", []) or []),
            public_autonomy=bool(block.get("public_autonomy", True)),
        )

    def to_dict(self) -> dict:
        """Return a plain-dict representation (round-trips via ``from_config``
        when fed back as ``{"opsec": <dict>}``)."""
        return {
            "enabled": self.enabled,
            "ua_rotation": self.ua_rotation,
            "doh": self.doh,
            "doh_provider": self.doh_provider,
            "min_gap_seconds": self.min_gap_seconds,
            "jitter_seconds": self.jitter_seconds,
            "rate_per_minute": self.rate_per_minute,
            "quiet_command_patterns": list(self.quiet_command_patterns),
            "noise_budget": self.noise_budget,
            "local_targets_off": self.local_targets_off,
            "local_cidrs": list(self.local_cidrs),
            "public_autonomy": self.public_autonomy,
        }

    def resolve_for_target(self, target_ip: str) -> "OpsecProfile":
        """Return the effective profile for a given target IP.

        Operator intent: OPSEC OFF for local/private targets (the operator's
        own lab box / RFC1918 network -- they own it and want the AI to move
        freely); OPSEC ON for public-routable targets (real external surface,
        keep pacing / UA rotation / quiet-commands / noise budget).

        When ``self.local_targets_off`` is true AND ``target_ip`` classifies as
        private/local (via :func:`tools.validation_utils.is_private_or_local_target`,
        which honors ``self.local_cidrs``), return a **disabled** profile
        (``OpsecProfile`` with all hardening fields off) that **preserves**
        ``local_targets_off`` / ``local_cidrs`` / ``public_autonomy`` so a
        later re-resolution against a public pivot target re-enables correctly.

        Otherwise (public target, or ``local_targets_off`` false) return
        ``self`` unchanged so the configured posture applies. A missing/empty
        ``target_ip`` returns ``self`` (no information -> keep configured
        posture, the safe default).
        """
        if not self.local_targets_off or not target_ip:
            return self
        # Lazy import keeps this module hermetic at import time (no tools.*
        # import side effects) per the opsec.py design constraints.
        from tools.validation_utils import is_private_or_local_target

        if not is_private_or_local_target(target_ip, list(self.local_cidrs)):
            return self
        # Local target -> fully disabled hardening, but keep the
        # target-awareness knobs so per-task re-resolution of a different
        # (public) target from this resolved profile still works.
        return OpsecProfile(
            enabled=False,
            ua_rotation=False,
            doh=False,
            doh_provider=self.doh_provider,
            min_gap_seconds=0.0,
            jitter_seconds=0.0,
            rate_per_minute=0,
            quiet_command_patterns=(),
            noise_budget=0,
            local_targets_off=self.local_targets_off,
            local_cidrs=self.local_cidrs,
            public_autonomy=self.public_autonomy,
        )


# ---------------------------------------------------------------------------
# OpsecManager
# ---------------------------------------------------------------------------

# Type aliases for injected callables.
RngFn = Callable[[], float]
FetchFn = Callable[..., Any]
SleepFn = Callable[[float], Any]


class OpsecManager:
    """Stateful OPSEC engine wrapping an :class:`OpsecProfile`.

    All network / time / randomness is injectable so tests are hermetic.
    """

    _UA_POOL: tuple[str, ...] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    )
    """8 realistic, modern browser User-Agent strings for UA rotation."""

    _DOH_URLS: dict[str, str] = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
    }

    _NOISY_PATTERNS: tuple[str, ...] = (
        "nmap -t5",
        "-t5",
        "--script=vuln",
        "masscan",
        "hydra",
        "nuclei",
        "ffuf",
        "gobuster",
        "dirb",
        "crackmapexec --shares",
        "crackmapexec",
        "nmap -sS -p-",
        "zmap",
        "rustscan -t",
        "sqlmap --dump",
        "nmap --script",
        "nbtscan",
        "enum4linux",
        "wpscan",
    )
    """Substring patterns (case-insensitive) used by :meth:`score_command_noise`."""

    _LOW_NOISE_REWRITES: tuple[tuple[str, str], ...] = (
        ("-t5", "-T2"),
        ("-t4", "-T2"),
        ("--script=vuln", "(drop --script=vuln)"),
        ("masscan", "nmap -sS -Pn"),
        ("crackmapexec", "smbclient -N"),
        ("nuclei", "nmap -sV"),
        ("nucleus", "nmap -sV"),
        ("ffuf", "nmap -sV"),
        ("gobuster", "nmap -sV"),
        ("dirb", "nmap -sV"),
    )
    """Single source of truth for low-noise rewrites, shared by
    :meth:`suggest_low_noise_alternative` (per-command rewrite) and the system
    prompt's OPSEC briefing (example list) so they cannot drift apart."""

    def __init__(
        self,
        profile: OpsecProfile,
        *,
        rng: Optional[RngFn] = None,
        fetch_fn: Optional[FetchFn] = None,
        rate_limiter: Any = None,
        sleep_fn: Optional[SleepFn] = None,
    ) -> None:
        self.profile = profile
        self._rng = rng
        self._fetch_fn = fetch_fn
        self._rate_limiter = rate_limiter
        self._sleep_fn = sleep_fn

    # -- helpers -----------------------------------------------------------

    def _rand(self) -> float:
        """Return a float in [0, 1) using the injected rng, or lazily-imported
        ``random.random`` when none was provided."""
        if self._rng is not None:
            return float(self._rng())
        import random  # lazy: no import-time side effect

        return random.random()

    # -- User-Agent --------------------------------------------------------

    def user_agent(self) -> str:
        """Return a User-Agent string.

        When ``profile.ua_rotation`` is on, pick from :attr:`_UA_POOL` using
        the (optionally injected) rng -- deterministic when an rng is injected.
        Otherwise return the fixed default ``BreachPilot/1.0``.
        """
        if self.profile.ua_rotation and self._UA_POOL:
            idx = int(self._rand() * len(self._UA_POOL)) % len(self._UA_POOL)
            return self._UA_POOL[idx]
        return "BreachPilot/1.0"

    # -- Pacing ------------------------------------------------------------

    def pacing_delay(self, aggression: str = "normal") -> float:
        """Compute the pacing delay (seconds) before the next action.

        ``base = profile.min_gap_seconds * AGGRESSION_FACTOR[aggression]``
        (unknown aggression -> factor 1.0). ``jitter = profile.jitter_seconds
        * rand()`` when ``jitter_seconds > 0`` else 0. Returns
        ``max(0.0, base + jitter)``. When the profile is disabled AND
        ``min_gap_seconds == 0`` the delay is exactly 0.0 (fast path).
        """
        if not self.profile.enabled and self.profile.min_gap_seconds == 0.0:
            return 0.0
        factor = AGGRESSION_FACTOR.get(aggression, 1.0)
        base = self.profile.min_gap_seconds * factor
        if self.profile.jitter_seconds > 0.0:
            jitter = self.profile.jitter_seconds * self._rand()
        else:
            jitter = 0.0
        return max(0.0, base + jitter)

    async def acquire_pacing(self, aggression: str = "normal") -> None:
        """Await any rate-limit token then sleep the pacing delay.

        When a ``rate_limiter`` with an async ``acquire(key, cost)`` is
        configured AND ``profile.rate_per_minute > 0``, await it for the
        ``"opsec"`` key. Then sleep :meth:`pacing_delay` seconds using
        ``asyncio.sleep`` (real or injected via ``sleep_fn`` for sync tests).

        Safe to call with no rate limiter -- just sleeps the delay.
        """
        if self._rate_limiter is not None and self.profile.rate_per_minute > 0:
            await self._rate_limiter.acquire("opsec", 1)
        delay = self.pacing_delay(aggression)
        if delay > 0:
            if self._sleep_fn is not None:
                result = self._sleep_fn(delay)
                # If the injected sleep returns an awaitable, await it.
                if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
                    await result  # type: ignore[misc]
            else:
                await asyncio.sleep(delay)

    # -- Noise scoring & quiet blocking -----------------------------------

    def score_command_noise(self, command: str) -> dict:
        """Score how noisy a command is.

        Returns ``{"score": int, "reasons": list[str], "noisy": bool}``.
        ``score`` is the number of distinct :attr:`_NOISY_PATTERNS` matched
        (case-insensitive substring). ``noisy`` is ``score > 0``. ``reasons``
        lists the matched patterns. Empty / ``None`` command -> score 0.
        """
        if not command:
            return {"score": 0, "reasons": [], "noisy": False}
        lowered = command.lower()
        reasons: list[str] = []
        for pat in self._NOISY_PATTERNS:
            if pat.lower() in lowered:
                # Avoid double-counting the same substring if a shorter and
                # longer pattern both match (e.g. "crackmapexec" and
                # "crackmapexec --shares"); keep the first occurrence but
                # still record each distinct matched pattern once.
                if pat not in reasons:
                    reasons.append(pat)
        score = len(reasons)
        return {"score": score, "reasons": reasons, "noisy": score > 0}

    def is_quiet_blocked(self, command: str) -> bool:
        """True iff OPSEC is enabled and any ``quiet_command_pattern`` is a
        case-insensitive substring of ``command``."""
        if not self.profile.enabled:
            return False
        if not command or not self.profile.quiet_command_patterns:
            return False
        lowered = command.lower()
        return any(p.lower() in lowered for p in self.profile.quiet_command_patterns)

    def suggest_low_noise_alternative(self, command: str) -> Optional[str]:
        """Heuristic rewrite of a noisy command into a quieter equivalent.

        Pure string replacement; never executes anything. Returns the
        rewritten command, or ``None`` when no rewrite applies.
        """
        if not command:
            return None
        lowered = command.lower()
        # (needle_lower, replacement). Order matters: more specific rewrites
        # first. The replacement replaces the first case-insensitive occurrence
        # of needle in the original command, preserving the rest of the casing.
        for needle, replacement in self._LOW_NOISE_REWRITES:
            idx = lowered.find(needle)
            if idx >= 0:
                return command[:idx] + replacement + command[idx + len(needle) :]
        return None

    # -- DNS-over-HTTPS ----------------------------------------------------

    def doh_resolve(self, hostname: str) -> list[str]:
        """Resolve ``hostname`` to a deduped list of IP strings.

        When ``profile.doh`` is on, query the configured DoH provider via the
        injected ``fetch_fn`` (or ``urllib`` when none). On ANY error --
        network, parse, bad provider -- fall back to ``socket.getaddrinfo``.
        When DoH is off, go straight to ``socket.getaddrinfo``. Never raises;
        returns ``[]`` on total failure.
        """
        if not self.profile.doh:
            return self._system_resolve(hostname)
        provider = self.profile.doh_provider
        base = self._DOH_URLS.get(provider)
        if base is None:
            return self._system_resolve(hostname)
        try:
            url = f"{base}?name={hostname}&type=A"
            headers: dict[str, str]
            if provider == "cloudflare":
                headers = {"Accept": "application/dns-json"}
            else:
                headers = {"Accept": "application/dns-json"}
            data = self._doh_fetch(url, headers)
            ips = self._parse_doh_answer(data)
            if ips:
                return _dedupe(ips)
        except Exception:
            pass
        # Fall back to the system resolver on any DoH failure.
        return self._system_resolve(hostname)

    def _doh_fetch(self, url: str, headers: dict[str, str]) -> bytes:
        """Fetch DoH bytes via the injected fetch_fn or urllib."""
        if self._fetch_fn is not None:
            data = self._fetch_fn(url, headers)
            # A fetch_fn may return str or bytes; normalize to bytes for JSON.
            if isinstance(data, str):
                return data.encode("utf-8")
            return data
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.read()

    @staticmethod
    def _parse_doh_answer(data: bytes) -> list[str]:
        """Parse the Answer array of a DoH JSON response into IP strings."""
        text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
        payload = json.loads(text)
        answers = payload.get("Answer") or []
        ips: list[str] = []
        for rec in answers:
            if not isinstance(rec, dict):
                continue
            # type 1 == A (IPv4); some providers also return IPv6 (type 28).
            rtype = rec.get("type")
            ip = rec.get("data")
            if isinstance(ip, str) and _looks_like_ip(ip):
                ips.append(ip)
            elif rtype == 1 and isinstance(ip, str) and _looks_like_ip(ip):
                ips.append(ip)
        return ips

    @staticmethod
    def _system_resolve(hostname: str) -> list[str]:
        """Resolve via ``socket.getaddrinfo``; never raises."""
        try:
            infos = socket.getaddrinfo(hostname, None)
        except Exception:
            return []
        ips: list[str] = []
        for info in infos:
            addr = info[4]
            if isinstance(addr, tuple) and addr:
                ip = addr[0]
                if isinstance(ip, str) and _looks_like_ip(ip):
                    ips.append(ip)
        return _dedupe(ips)

    # -- Factory -----------------------------------------------------------

    @classmethod
    def from_config(cls, cfg: dict, **kwargs: Any) -> "OpsecManager":
        """Build an :class:`OpsecManager` from the full config dict.

        Reads ``cfg.get("opsec", {})`` into an :class:`OpsecProfile` and
        forwards any remaining constructor kwargs (``rng``, ``fetch_fn``,
        ``rate_limiter``, ``sleep_fn``).
        """
        profile = OpsecProfile.from_config(cfg or {})
        return cls(profile, **kwargs)

    # -- Target-aware resolution ------------------------------------------

    def resolve_for_target(self, target_ip: str) -> "OpsecManager":
        """Return the effective manager for a given target IP.

        Delegates to :meth:`OpsecProfile.resolve_for_target`: a local/private
        target with ``local_targets_off`` yields a manager wrapping a disabled
        profile (OPSEC off -- pacing no-op, no UA rotation, no quiet-blocking);
        a public target returns ``self`` unchanged (configured posture ON).
        The resolved manager shares this manager's injected rng / fetch_fn /
        rate_limiter / sleep_fn so deterministic tests stay deterministic.
        """
        resolved = self.profile.resolve_for_target(target_ip)
        if resolved is self.profile:
            return self
        return OpsecManager(
            resolved,
            rng=self._rng,
            fetch_fn=self._fetch_fn,
            rate_limiter=self._rate_limiter,
            sleep_fn=self._sleep_fn,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedupe(items: Sequence[str]) -> list[str]:
    """Order-preserving dedupe."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _looks_like_ip(text: str) -> bool:
    """Cheap check that a string is an IP literal (v4 or v6), not a hostname.

    Used only to filter DoH Answer records -- never authoritative.
    """
    if not text or " " in text or "/" in text:
        return False
    # IPv4 dotted-quad
    if text.count(".") == 3:
        parts = text.split(".")
        if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
            return True
    # IPv6 contains ':' (and possibly '::')
    if ":" in text:
        return True
    return False


# ---------------------------------------------------------------------------
# Process-global UA rotation (for egress sites)
# ---------------------------------------------------------------------------

_DEFAULT_PROFILE = OpsecProfile()
"""Module-level default profile (OPSEC off). Mutated only via :func:`configure`."""

_process_manager: Optional[OpsecManager] = None


def configure(profile: OpsecProfile, **kwargs: Any) -> None:
    """Set the process-global OPSEC manager from a profile.

    Accepts the same injected callables as :class:`OpsecManager` so callers
    can wire a deterministic rng / fetch_fn at process startup.
    """
    global _process_manager
    _process_manager = OpsecManager(profile, **kwargs)


def process_user_agent(default: str = "BreachPilot/1.0") -> str:
    """Return a User-Agent for egress sites.

    When OPSEC is configured **and** UA rotation is on, returns a pool UA from
    the configured manager. Otherwise returns ``default`` unchanged -- so
    egress sites can call ``process_user_agent("BreachPilot-OSINT/1.0")`` with
    zero behavior change when OPSEC is not configured, and get rotating UAs
    when it is.
    """
    mgr = _process_manager
    if mgr is not None and mgr.profile.ua_rotation:
        return mgr.user_agent()
    return default
