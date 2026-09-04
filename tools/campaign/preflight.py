"""Campaign-entry preflight — target resolve / dedupe / scope-check filter.

Extracted from ``AutonomousOrchestrator`` (see
``tools/campaign/orchestrator.py``) to keep the orchestrator under 500
lines. Bound onto ``AutonomousOrchestrator`` after its definition, so
``self._preflight_targets`` call sites and tests keep working unchanged.
"""

from __future__ import annotations

from tools.logging_setup import get_logger

logger = get_logger()


def _preflight_targets(self, targets: list[str]) -> list[str]:
    """Resolve, de-duplicate, scope-check and filter the campaign target list.

    Runs before any scan is fired. Each filter is opt-in (default off), so
    a single-IP campaign is byte-identical to before this method existed.

    1. **Scope gate pre-check** -- every target must already be authorized
       via the same matcher the MCP tool layer uses
       (``_check_allowlist``). When ``exploit.require_explicit_allowlist``
       is False this is a no-op. This is the "avoid stuff that can't be
       attacked" lock applied one layer earlier: previously an unauthorized
       target still got a full Nmap scan before the tool-layer gate ever
       fired.
    2. **Non-routable filter** -- drop RFC1918 / link-local / reserved
       addresses that are not the operator's own host. Those are handled
       by the local-takeover playbook (``is_local_target``), not by a
       network campaign. ``169.254.169.254`` and ``0.0.0.0`` used to get
       scanned for free.
    3. **Dedup by resolved IP** -- collapse duplicate IPs, CIDR overlap,
       and hosts resolving to the same IP. Domains that fail DNS are kept
       (they may still be attackable via the hostname).

    Returns the filtered list. Skips are recorded as timeline events on a
    fresh ``AttackState`` so they survive into ``attack_states.json``.
    """
    if not targets:
        return []

    from tools.mcp_shared import _check_allowlist
    from tools.validation_utils import (
        is_local_target,
        is_private_or_local_target,
        resolve_target_to_ip,
    )

    seen_ips: set[str] = set()
    kept: list[str] = []

    for target in targets:
        target = (target or "").strip()
        if not target:
            continue

        # 1. Scope gate pre-check (no-op when allowlist is off). Uses the
        # same matcher the MCP tool layer uses so the lock is applied one
        # layer earlier: previously an unauthorized target still got a full
        # Nmap scan before the tool-layer gate ever fired.
        allowed, reason = _check_allowlist(target, self._mission)
        if not allowed:
            state = self.get_state(target)
            state.add_timeline_event(
                "target_skipped_out_of_scope",
                f"Target {target} is not authorized: {reason}; skipping",
                {"target": target, "reason": reason},
            )
            logger.info(f"[PREFLIGHT] {target} out of scope -- skipping")
            continue

        # Resolve for classification / dedup. A domain that fails DNS is
        # kept verbatim (don't drop it -- it may be attackable by name).
        resolved = resolve_target_to_ip(target)
        effective = resolved or target

        # 2. Non-routable filter. The operator's own host is NOT skipped
        # here -- it has its own local-takeover path in _attack_target.
        if self._skip_non_routable and is_private_or_local_target(effective):
            if not is_local_target(effective):
                state = self.get_state(target)
                state.add_timeline_event(
                    "target_skipped_non_routable",
                    f"Target {target} is non-routable ({effective}); skipping network campaign",
                    {"target": target, "resolved_ip": effective or ""},
                )
                logger.info(f"[PREFLIGHT] {target} non-routable -- skipping")
                continue

        # 3. Dedup by resolved IP (or the literal when resolution failed).
        dedup_key = effective if resolved else target
        if dedup_key in seen_ips:
            state = self.get_state(target)
            state.add_timeline_event(
                "target_dedup",
                f"Target {target} resolves to {dedup_key}; already scheduled -- skipping duplicate",
                {"target": target, "resolved_ip": dedup_key},
            )
            logger.info(f"[PREFLIGHT] {target} duplicate of {dedup_key} -- skipping")
            continue
        seen_ips.add(dedup_key)

        kept.append(target)

    if len(kept) != len(targets):
        logger.info(f"[PREFLIGHT] {len(targets)} target(s) -> {len(kept)} after preflight")
    return kept
