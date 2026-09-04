"""Producer/consumer graph over the closed artifact vocabulary.

Shared by the campaign prereq scheduler (``tools/campaign/orchestrator.py``)
and planner integration tests. All ranking is deterministic: cost order
(low < medium < high), read-only preferred on ties, then name.
"""

from __future__ import annotations

from tools.attack_modules.artifacts import TERMINAL_ARTIFACTS, is_satisfied, normalize
from tools.attack_modules.base import AttackModule, ModuleContext

_COST_ORDER = {"low": 0, "medium": 1, "high": 2}


def _cost_rank(mod: AttackModule) -> tuple[int, int, str]:
    # getattr-tolerant: test fakes expose only .name.
    return (
        _COST_ORDER.get(getattr(mod, "cost", "medium"), 1),
        0 if getattr(mod, "read_only", False) else 1,
        getattr(mod, "name", ""),
    )


def rank_producers(
    artifact_kind: str,
    ctx: ModuleContext | None = None,
    *,
    exclude: str = "",
    modules: list[AttackModule] | None = None,
) -> list[AttackModule]:
    """Producers of ``artifact_kind``, cheapest/read-only first.

    When ``ctx`` is given, producers whose own ``requires`` are unsatisfied
    sort after satisfiable ones (but are still returned — a demoted producer
    beats no producer). ``exclude`` skips a module name (no self-recovery).
    """
    from tools.attack_modules.registry import list_modules

    kind = normalize(artifact_kind)
    if modules is not None:
        # Explicitly supplied candidates (e.g. a mocked seam) are trusted as
        # producers already — only exclude + order, never re-filter (mocks
        # may not carry .produces).
        matches = list(modules)
    else:
        pool = list_modules()
        matches = [m for m in pool if kind in {normalize(p) for p in getattr(m, "produces", []) or []}]
    if exclude:
        matches = [m for m in matches if getattr(m, "name", "").lower() != exclude.lower()]

    def _key(m: AttackModule) -> tuple[int, int, int, str]:
        cost, ro, name = _cost_rank(m)
        blocked = 0
        if ctx is not None:
            missing = [r for r in getattr(m, "requires", []) or [] if not is_satisfied(r, ctx)]
            blocked = len(missing)
        return (blocked, cost, ro, name)

    matches.sort(key=_key)
    return matches


def missing_prerequisites(mod: AttackModule, ctx: ModuleContext) -> list[str]:
    """Declared ``requires`` entries not satisfiable from ``ctx`` (closed vocab)."""
    return [r for r in mod.requires if not is_satisfied(r, ctx)]


def producers_for(kind: str, modules: list[AttackModule] | None = None) -> list[AttackModule]:
    """All modules producing ``kind`` (unsorted; use ``rank_producers`` to order)."""
    from tools.attack_modules.registry import list_modules

    k = normalize(kind)
    pool = modules if modules is not None else list_modules()
    return [m for m in pool if k in {normalize(p) for p in m.produces}]


def consumers_of(kind: str, modules: list[AttackModule] | None = None) -> list[AttackModule]:
    """All modules requiring ``kind``."""
    from tools.attack_modules.registry import list_modules

    k = normalize(kind)
    pool = modules if modules is not None else list_modules()
    return [m for m in pool if k in {normalize(r) for r in m.requires}]


def chain_to(
    target_kind: str,
    ctx: ModuleContext,
    *,
    depth: int = 2,
    modules: list[AttackModule] | None = None,
) -> list[list[AttackModule]]:
    """BFS chains ``[producer..., consumer]`` yielding ``target_kind``.

    Each chain ends in a module producing ``target_kind`` whose own
    prerequisites are either satisfied by ``ctx`` or produced by an earlier
    link (recursively, up to ``depth``). Cycle-guarded via visited names.
    Sorted cheapest-first by summed cost rank. Returns [] when unsatisfiable.
    """
    from tools.attack_modules.registry import list_modules

    pool = modules if modules is not None else list_modules()
    target = normalize(target_kind)
    results: list[list[AttackModule]] = []

    def _satisfied_or_provided(req: str, provided: set[str]) -> bool:
        return is_satisfied(req, ctx) or normalize(req) in provided

    # Seed: direct producers.
    frontier: list[tuple[AttackModule, list[AttackModule], set[str]]] = []
    for mod in rank_producers(target, ctx, modules=pool):
        frontier.append((mod, [mod], {normalize(p) for p in mod.produces}))

    visited: set[tuple[str, ...]] = set()
    while frontier:
        mod, chain, provided = frontier.pop(0)
        key = tuple(m.name for m in chain)
        if key in visited:
            continue
        visited.add(key)
        missing = [r for r in mod.requires if not _satisfied_or_provided(r, provided)]
        if not missing:
            results.append(chain)
            continue
        if len(chain) > depth:
            continue
        # Expand the first missing req with its own ranked producers.
        req = missing[0]
        for prod in rank_producers(req, ctx, modules=pool):
            if prod.name in {m.name for m in chain}:
                continue  # cycle guard
            new_provided = provided | {normalize(p) for p in prod.produces}
            frontier.append((mod, [prod, *chain], new_provided))

    def _chain_cost(chain: list[AttackModule]) -> tuple[int, int]:
        return (
            sum(_COST_ORDER.get(m.cost, 1) for m in chain),
            sum(0 if m.read_only else 1 for m in chain),
        )

    results.sort(key=lambda c: (_chain_cost(c), [m.name for m in c]))
    return results


def orphan_requires(modules: list[AttackModule] | None = None) -> dict[str, list[str]]:
    """Map module name -> required kinds with no producer (excluding terminals)."""
    from tools.attack_modules.registry import list_modules

    pool = modules if modules is not None else list_modules()
    produced = {normalize(p) for m in pool for p in m.produces}
    orphans: dict[str, list[str]] = {}
    for m in pool:
        missing = [r for r in m.requires if normalize(r) not in produced]
        if missing:
            orphans[m.name] = missing
    return orphans


def dead_end_produces(modules: list[AttackModule] | None = None) -> dict[str, list[str]]:
    """Map module name -> produced kinds with no consumer (excluding terminals)."""
    from tools.attack_modules.registry import list_modules

    pool = modules if modules is not None else list_modules()
    required = {normalize(r) for m in pool for r in m.requires}
    dead: dict[str, list[str]] = {}
    for m in pool:
        ends = [p for p in m.produces if normalize(p) not in required and normalize(p) not in TERMINAL_ARTIFACTS]
        if ends:
            dead[m.name] = ends
    return dead


# Fungible currency artifacts: credentials/hash_artifact flow both ways
# through roast/crack/relay modules by design (roast needs a user list OR
# creds, cracking needs hashes, PtH needs hashes). A kind-level 2-cycle
# through these is composition, not deadlock — artifacts are never consumed,
# and chain_to's visited-set guards termination. Only cycles through
# non-currency kinds indicate a real planning loop.
_CURRENCY_KINDS = frozenset({"credentials", "hash_artifact", "user_list", "foothold", "shell", "session"})


def find_cycle(modules: list[AttackModule] | None = None) -> list[str]:
    """Return one requires->produces cycle through non-currency kinds, else [].

    Currency artifacts (credentials/hash_artifact/...) cycle by design; only
    structural kinds (priv levels, posture, leaks) looping back indicate a
    broken chain.
    """
    from tools.attack_modules.registry import list_modules

    pool = modules if modules is not None else list_modules()
    prod_of: dict[str, list[str]] = {}
    for m in pool:
        for p in m.produces:
            prod_of.setdefault(normalize(p), []).append(m.name)
    names = {m.name: m for m in pool}
    for a in pool:
        for r in a.requires:
            if normalize(r) in _CURRENCY_KINDS:
                continue
            for b_name in prod_of.get(normalize(r), []):
                if b_name == a.name:
                    continue
                b = names.get(b_name)
                if b is None:
                    continue
                for r2 in b.requires:
                    if normalize(r2) in _CURRENCY_KINDS:
                        continue
                    for c_name in prod_of.get(normalize(r2), []):
                        if c_name == a.name:
                            return [a.name, b_name, a.name]
    return []
