"""Regression tests for Tier 1.7 — ExperienceStore-driven module ranking.

Covers the activation of the dormant ``ExperienceStore.get_all_confidences``
for ``find_modules`` ranking: a module that has historically succeeded against
a ``service:version:os`` signature is promoted, one that has historically
failed is demoted below untried modules (which stay neutral), and the static
applicability score remains the hard gate. Also covers the swarm wiring that
threads the shared experience store into ``find_modules`` and
``run_exploit_agent`` so the exploit loop's outcome writes and the swarm's
module selection share one database.

The blend tests use RELATIVE comparisons against the no-store baseline rather
than absolute scores (module static scores vary: SSHBruteForce = service 30 +
port 22 20 = 50, not 30). This keeps the assertions robust to module
definition drift and tests the actual behavior -- that experience changes the
RELATIVE ordering -- instead of hardcoding numbers.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from db import DatabaseManager
from tools.attack_modules import (
    AttackModule,
    ModuleContext,
    SSHBruteForce,
    _module_target_signature,
    find_modules,
)
from tools.experience_store import ExperienceStore

# ── Fakes ─────────────────────────────────────────────────────────────────


class FakeExperience:
    """Duck-typed stand-in for ExperienceStore.get_all_confidences.

    ``confs`` maps target_signature -> {action_type: confidence}. No
    min-samples gate (that is exercised in test_semantic_memory.py); here we
    test the BLEND in find_modules against whatever get_all_confidences returns.
    """

    def __init__(self, confs: dict[str, dict[str, float]] | None = None,
                 raises: bool = False) -> None:
        self._confs = confs or {}
        self._raises = raises
        self.queries: list[str] = []

    def get_all_confidences(self, target_signature: str) -> dict[str, float]:
        if self._raises:
            raise RuntimeError("db down")
        self.queries.append(target_signature)
        return dict(self._confs.get(target_signature, {}))


def _ctx_ssh(version: str = "8.2", os_hint: str = "linux") -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.5",
        target_os=os_hint,
        services=[{"service": "ssh", "port": "22/tcp", "version": version}],
        cves=[],
    )


def _static_scores(ctx: ModuleContext) -> dict[str, float]:
    """Baseline ranking without a store: {module_name: static_score}."""
    return {m.name: s for s, m in find_modules(ctx, experience_store=None)}


# ═══════════════════════════════════════════════════════════════════════════
# Primitive — find_modules experience blending
# ═══════════════════════════════════════════════════════════════════════════


def test_find_modules_no_store_is_static_and_back_compat():
    """No experience store -> pure static applicability, sorted desc, zeros
    filtered. (Back-compat with all pre-1.7 callers.)"""
    scored = find_modules(_ctx_ssh())
    assert len(scored) > 0
    scores = [s for s, _ in scored]
    assert scores == sorted(scores, reverse=True)
    names = [m.name for _, m in scored]
    assert "SSHBruteForce" in names
    assert "Log4jRCE" not in names  # not applicable to ssh -> filtered


def test_find_modules_promotes_successful_module():
    """A module with high historical confidence ranks ABOVE its own static
    score (promoted), while an untried module stays at its static score."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(confs={
        "ssh:8.2:linux": {"SSHBruteForce:generate": 0.9},
    })
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    # SSHBruteForce promoted above its static baseline.
    assert with_store["SSHBruteForce"] > static["SSHBruteForce"]
    # The ssh signature was queried.
    assert "ssh:8.2:linux" in exp.queries


def test_find_modules_demotes_failing_module_below_untried():
    """A module that has consistently failed (confidence 0.0) is demoted BELOW
    its own static score AND below an untried module (neutral 0.5) that shares
    the same static applicability."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(confs={
        "ssh:8.2:linux": {"SSHBruteForce:generate": 0.0},  # all failures -> -10
    })
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    # SSHBruteForce demoted below its static baseline.
    assert with_store["SSHBruteForce"] < static["SSHBruteForce"]
    # Find an untried ssh module (no recorded history for it) with the same
    # static score as SSHBruteForce; it must now rank above the demoted one.
    ssh_baseline = static["SSHBruteForce"]
    untried = [
        (m, s) for m, s in static.items()
        if m != "SSHBruteForce" and s == ssh_baseline
    ]
    if untried:
        untried_name = untried[0][0]
        # Untried module's with-store score == its static (neutral), so it must
        # exceed the demoted SSHBruteForce.
        assert with_store[untried_name] == pytest.approx(static[untried_name])
        assert with_store[untried_name] > with_store["SSHBruteForce"]


def test_find_modules_neutral_when_no_recorded_data():
    """A signature with no recorded outcomes -> confidence 0.5 -> no swing:
    every module's with-store score equals its static score."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(confs={})  # nothing recorded
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    assert "ssh:8.2:linux" in exp.queries  # store was consulted
    for name, baseline in static.items():
        assert with_store[name] == pytest.approx(baseline), \
            f"{name} shifted despite no recorded data"


def test_find_modules_store_exception_is_neutral_and_non_fatal():
    """If the store raises, ranking falls back to neutral (no crash)."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(raises=True)
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    for name, baseline in static.items():
        assert with_store[name] == pytest.approx(baseline)


def test_find_modules_zero_applicability_excluded_even_with_high_confidence():
    """The static applicability is a hard gate: a non-applicable module is
    never included, even if it has a perfect success history."""
    exp = FakeExperience(confs={
        "http:1.18.0:linux": {"Log4jRCE:generate": 1.0},
    })
    scored = find_modules(_ctx_ssh(), experience_store=exp)
    names = [m.name for _, m in scored]
    assert "Log4jRCE" not in names  # not applicable to ssh -> excluded


def test_find_modules_aggregates_across_strategies():
    """Confidence is averaged across all mutation strategies recorded for a
    module (action_type = '<module>:<strategy>'). Mean 0.5 -> neutral."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(confs={
        "ssh:8.2:linux": {
            "SSHBruteForce:generate": 1.0,
            "SSHBruteForce:parameter_tweak": 0.0,
            "OtherModule:generate": 0.5,  # different module, excluded from SSH avg
        },
    })
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    # Mean of (1.0, 0.0) = 0.5 -> neutral -> no swing vs static.
    assert with_store["SSHBruteForce"] == pytest.approx(static["SSHBruteForce"])


def test_find_modules_aggregate_promotes_when_majority_success():
    """A module with a 2/3 success rate (mean ~0.67) is promoted above static."""
    static = _static_scores(_ctx_ssh())
    exp = FakeExperience(confs={
        "ssh:8.2:linux": {
            "SSHBruteForce:generate": 1.0,
            "SSHBruteForce:parameter_tweak": 1.0,
            "SSHBruteForce:encoding_change": 0.0,
        },
    })
    with_store = {m.name: s for s, m in find_modules(_ctx_ssh(), experience_store=exp)}
    assert with_store["SSHBruteForce"] > static["SSHBruteForce"]


# ── Helper — _module_target_signature ──────────────────────────────────────


def test_module_target_signature_picks_present_service():
    sig = _module_target_signature(SSHBruteForce(), _ctx_ssh(version="9.0", os_hint="linux"))
    assert sig == "ssh:9.0:linux"


def test_module_target_signature_unknown_os_fallback():
    sig = _module_target_signature(SSHBruteForce(), ModuleContext(
        target_ip="10.0.0.5", target_os=None,
        services=[{"service": "ssh", "port": "22/tcp", "version": ""}],
    ))
    assert sig == "ssh::unknown"


def test_module_target_signature_none_when_no_target_services():
    class NoServices:
        target_services: list[str] = []
    assert _module_target_signature(NoServices(), _ctx_ssh()) is None


# ── Helper — _module_primary_service (read/write coherence) ────────────────


class _MultiSvcModule(AttackModule):
    """Multi-service module (mirrors SMBRelay's target_services) for the
    read/write coherence test. Recon reports a NON-first-declared service."""
    name = "SMBRelay"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {}

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return ""


class _RecordingMutator:
    """Captures the (service_name, version, os_hint) the WRITE side
    (generate_dynamic_script -> craft_initial) records against, so we can
    compare it to the READ side (_module_target_signature) query signature."""

    def __init__(self) -> None:
        self.captured: dict[str, Any] = {}

    def craft_initial(self, *, target_ip, service_name, version,
                      os_hint, module_name):
        self.captured = {
            "service_name": service_name,
            "version": version,
            "os_hint": os_hint,
        }
        from types import SimpleNamespace
        return SimpleNamespace(script="x")


def test_read_write_signature_coherence_for_multi_service_module():
    """Tier 1.7 read/write coherence: generate_dynamic_script (write side)
    must record against the SAME service+version signature that
    _module_target_signature (read side) queries, even for a multi-service
    module where recon reports a NON-first-declared service string.

    Pre-fix the write side hardcoded target_services[0] ('microsoft-ds'),
    found no matching service in ctx, and recorded an empty version, while the
    read side picked the present 'smb' with its real version -> the queried
    signature never matched the recorded one -> historical confidence was
    silently never applied for ~12 multi-service modules. This test would have
    caught that: it asserts byte-equal read==write signatures AND that the
    present 'smb' (not 'microsoft-ds') with its version is used on BOTH sides.
    """
    ctx = ModuleContext(
        target_ip="10.0.0.5", target_os="linux",
        services=[{"service": "smb", "port": "445/tcp", "version": "3.1.1"}],
        cves=[],
    )
    mod = _MultiSvcModule()

    # READ side: the signature find_modules will query.
    read_sig = _module_target_signature(mod, ctx)
    assert read_sig is not None

    # WRITE side: what generate_dynamic_script records against.
    mut = _RecordingMutator()
    mod.generate_dynamic_script(ctx, mutator=mut)

    write_sig = f"{mut.captured['service_name']}:{mut.captured['version'] or ''}:{mut.captured['os_hint']}"

    # Both sides must agree on service AND version.
    assert read_sig == write_sig, (
        f"read/write signature divergence: read={read_sig!r} write={write_sig!r}"
    )
    # And specifically: the PRESENT 'smb' (not the first-declared 'microsoft-ds')
    # with its real version, on both sides.
    assert mut.captured["service_name"] == "smb"
    assert mut.captured["version"] == "3.1.1"
    assert read_sig == "smb:3.1.1:linux"


def test_multi_service_module_experience_applies_when_recon_reports_present_service():
    """End-to-end coherence: the WRITE side (generate_dynamic_script) records
    an outcome against a signature it derives from ctx; the READ side
    (find_modules) must INDEPENDENTLY arrive at the SAME signature to find that
    record and promote the module. We seed the store at the signature the
    WRITE side actually emits (captured via the mutator), NOT at a signature we
    compute ourselves -- so this is behavioral, not tautological: pre-fix the
    write side emitted 'microsoft-ds::linux' while the read side queried
    'smb:3.1.1:linux', the seed and query would miss, and promotion would NOT
    happen -> the test would FAIL, catching the bug."""
    ctx = ModuleContext(
        target_ip="10.0.0.5", target_os="linux",
        services=[{"service": "smb", "port": "445/tcp", "version": "3.1.1"}],
        cves=[],
    )
    mod = _MultiSvcModule()

    # Drive the WRITE side to capture the signature it records against.
    mut = _RecordingMutator()
    mod.generate_dynamic_script(ctx, mutator=mut)
    write_sig = (
        f"{mut.captured['service_name']}:"
        f"{mut.captured['version'] or ''}:"
        f"{mut.captured['os_hint']}"
    )

    # Seed the store at exactly the WRITE-side signature (a perfect success).
    exp = FakeExperience(confs={write_sig: {"SMBRelay:generate": 1.0}})

    static = {m.name: s for s, m in find_modules(ctx, experience_store=None)}
    with_store = {m.name: s for s, m in find_modules(ctx, experience_store=exp)}

    # The READ side must have consulted the store at the WRITE-side signature.
    # Pre-fix the read side queried 'smb:3.1.1:linux' while write seeded
    # 'microsoft-ds::linux' -> this membership check would fail.
    assert write_sig in exp.queries, (
        f"read side queried {exp.queries!r}; never the write-side sig {write_sig!r}"
    )
    # The module was PROMOTED above its static baseline -- the read side found
    # the write-side record. Pre-fix: no match -> no promote -> assertion fails.
    assert with_store["SMBRelay"] > static["SMBRelay"], (
        f"SMBRelay not promoted despite a perfect record at write-side sig "
        f"{write_sig!r}: static={static['SMBRelay']} "
        f"with_store={with_store['SMBRelay']}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Swarm wiring — vuln_agent threads the shared store into find_modules
# ═══════════════════════════════════════════════════════════════════════════


def test_vuln_agent_passes_experience_store_to_find_modules(monkeypatch):
    """vuln_agent.run reads context['experience'] and forwards it to
    find_modules so module ranking uses the swarm's shared store."""
    from tools.swarm.agents import vuln_agent as va

    captured: dict[str, Any] = {}
    def fake_find_modules(ctx, experience_store=None):
        captured["store"] = experience_store
        captured["ctx"] = ctx
        return []  # no modules -> short-circuits the per-service loop body
    monkeypatch.setattr(va, "find_modules", fake_find_modules)
    monkeypatch.setattr(va.NVDClient, "search_sync", lambda self, q: [])
    monkeypatch.setattr(va.ExploitSearch, "search_exploit_db", lambda self, q: "")
    monkeypatch.setattr(va.ExploitSearch, "search_web_exploit", lambda self, q: "")

    fake_store = FakeExperience()
    agent = va.VulnAgent()
    task = {"target": "10.0.0.5", "task_id": "V-1",
            "services": [{"service": "ssh", "port": "22/tcp", "version": "8.2"}]}
    context = {"config": {}, "model_client": None, "blackboard": {},
               "experience": fake_store}
    agent.run(task, context)
    assert captured["store"] is fake_store, "vuln_agent did not forward the shared store"


def test_vuln_agent_no_experience_store_is_static_back_compat(monkeypatch):
    """No store in context -> find_modules is called with None (static ranking),
    and run() does not crash."""
    from tools.swarm.agents import vuln_agent as va

    captured: dict[str, Any] = {}
    def fake_find_modules(ctx, experience_store=None):
        captured["store"] = experience_store
        return []
    monkeypatch.setattr(va, "find_modules", fake_find_modules)
    monkeypatch.setattr(va.NVDClient, "search_sync", lambda self, q: [])
    monkeypatch.setattr(va.ExploitSearch, "search_exploit_db", lambda self, q: "")
    monkeypatch.setattr(va.ExploitSearch, "search_web_exploit", lambda self, q: "")

    agent = va.VulnAgent()
    task = {"target": "10.0.0.5", "task_id": "V-2",
            "services": [{"service": "ssh", "port": "22/tcp", "version": "8.2"}]}
    context = {"config": {}, "model_client": None, "blackboard": {}}
    agent.run(task, context)
    assert captured["store"] is None


# ═══════════════════════════════════════════════════════════════════════════
# run_exploit_agent — a provided store is used, not rebuilt on get_default_db
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_run_exploit_agent_uses_provided_experience_store(monkeypatch, tmp_path):
    """When the caller passes experience_store, run_exploit_agent must NOT
    rebuild one on get_default_db() -- the provided store reaches the
    ExploitMutator. We spy on ExploitMutator.__init__ to capture the store then
    RAISE, so run_exploit_agent bails right after the mutator is constructed
    (no agent loop runs). Triple non-vacuous assertion: the spy fired (the
    store block was reached), the provided store is the one captured, and
    get_default_db was never called (no rebuild)."""
    import db as _db
    from tools import exploit_agent as ea
    from tools.exploit_mutator import ExploitMutator

    class RecordingStore:
        def get_all_confidences(self, sig): return {}
        def get_confidence(self, sig, action): return 0.5
        def update_from_exploit_result(self, **kw): pass
        def update_from_result(self, *a, **k): pass

    provided = RecordingStore()
    mutator_stores: list[Any] = []
    real_init = ExploitMutator.__init__

    def spy_init(self, *args, **kwargs):
        mutator_stores.append(kwargs.get("experience_store"))
        raise RuntimeError("stop after capture -- do not run the agent loop")

    monkeypatch.setattr(ExploitMutator, "__init__", spy_init)

    gdb_calls: list[bool] = []
    def fake_get_default_db():
        gdb_calls.append(True)
        return _db.DatabaseManager(tmp_path / "fallback.db")
    monkeypatch.setattr("db.get_default_db", fake_get_default_db)

    settings = ea.ExploitSettings(
        enabled=True, mode="standalone",
        permission=ea.ExploitPermission.FULL_ACCESS,
        attack_mode=True, max_rounds=1, max_commands_per_session=5,
        adaptive_exploits_enabled=True,  # so the mutator block (spy target) runs
    )
    policy = ea.ExploitPolicy(settings, tmp_path)

    # The spy raises at mutator construction, so run_exploit_agent throws
    # before entering the loop; we don't need a real client/session.
    with pytest.raises(RuntimeError, match="stop after capture"):
        await ea.run_exploit_agent(
            client=MagicMock(), model="test-model", session=AsyncMock(),
            exploit_tools=[], policy=policy, target_ip="10.0.0.1",
            experience_store=provided,
            semantic_memory=object(),  # truthy -> skips semantic get_default_db rebuild
        )

    # Non-vacuous: the mutator block was reached (spy fired)...
    assert mutator_stores, "ExploitMutator was never constructed (test did not reach the store block)"
    # ...the provided store is the one wired (not a rebuilt one)...
    assert mutator_stores[0] is provided, \
        "run_exploit_agent rebuilt its own store instead of using the provided one"
    # ...and get_default_db was NOT called for the experience store rebuild.
    assert not gdb_calls, \
        "run_exploit_agent called get_default_db despite a provided experience_store"


# ═══════════════════════════════════════════════════════════════════════════
# H13 — get_confidence / get_all_confidences exclude distilled lesson rows
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def exp_db(tmp_path):
    """Fresh DatabaseManager with schema initialized for ExperienceStore tests."""
    db = DatabaseManager(tmp_path / "research.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    yield db


def _insert_lessons_row(conn, *, target_signature, action_type, outcome,
                       embedding_json, confidence=0.5):
    """Insert a lessons row directly, mirroring record_outcome (embedding '[]')
    vs SemanticMemoryManager.store_lesson (embedding '[...]')."""
    from db import _new_id, _now_iso
    conn.execute(
        """INSERT INTO lessons(id, pattern_hash, target_signature, action_type,
           outcome, confidence, embedding_json, metadata_json, created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            _new_id("EXP"),
            f"{target_signature}:{action_type}",
            target_signature,
            action_type,
            outcome,
            confidence,
            embedding_json,
            "[]",
            _now_iso(),
        ),
    )


def test_get_confidence_excludes_distilled_lesson_rows(exp_db):
    """H13: get_confidence must count only trial-outcome rows
    (embedding_json = '[]'), not distilled SemanticMemoryManager.store_lesson
    rows (embedding_json = '[...]'). Pre-fix a lesson row's outcome was counted
    as a trial outcome, skewing the Beta mean."""
    store = ExperienceStore(exp_db, min_samples=1)

    # A real trial outcome (embedding_json = '[]') -- a single success.
    with exp_db.connection(write=True) as conn:
        _insert_lessons_row(
            conn,
            target_signature="ssh:8.2:linux",
            action_type="SSHBruteForce",
            outcome="success",
            embedding_json="[]",
        )
        # A distilled lesson row (embedding_json = '[...]') carrying a *failure*
        # outcome, written by SemanticMemoryManager.store_lesson.
        _insert_lessons_row(
            conn,
            target_signature="ssh:8.2:linux",
            action_type="SSHBruteForce",
            outcome="failure",
            embedding_json="[0.5, 0.5, 0.5]",
        )

    # Only the trial row counts: n=1 success -> Beta(2,1) mean = 2/3.
    # Pre-fix the lesson row's failure would also count -> n=2 (1 success, 1
    # failure) -> Beta(2,2) mean = 0.5, masking the success signal.
    conf = store.get_confidence("ssh:8.2:linux", "SSHBruteForce")
    assert conf == pytest.approx(2.0 / 3.0, abs=0.01), (
        f"lesson row leaked into trial count: got {conf}, expected ~0.667"
    )
    # Sanity: the lesson row did not bring the mean down to 0.5.
    assert conf > 0.6


def test_get_all_confidences_excludes_distilled_lesson_rows(exp_db):
    """H13: get_all_confidences must also exclude distilled lesson rows so the
    per-action Beta means only reflect real trial outcomes."""
    store = ExperienceStore(exp_db, min_samples=1)

    with exp_db.connection(write=True) as conn:
        # Two real trial successes for EternalBlue.
        for _ in range(2):
            _insert_lessons_row(
                conn,
                target_signature="smb:windows10",
                action_type="EternalBlue",
                outcome="success",
                embedding_json="[]",
            )
        # A distilled lesson row for EternalBlue carrying a *failure* outcome.
        _insert_lessons_row(
            conn,
            target_signature="smb:windows10",
            action_type="EternalBlue",
            outcome="failure",
            embedding_json="[0.1, 0.2, 0.3]",
        )

    all_conf = store.get_all_confidences("smb:windows10")
    # Only the two trial successes count: Beta(3,1) mean = 0.75.
    # Pre-fix the lesson's failure would count -> Beta(3,2) mean = 0.6.
    assert "EternalBlue" in all_conf
    assert all_conf["EternalBlue"] == pytest.approx(0.75, abs=0.01), (
        f"lesson row leaked into get_all_confidences: got "
        f"{all_conf['EternalBlue']}, expected ~0.75"
    )
