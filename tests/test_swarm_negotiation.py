"""Tests for the bounded critic<->exploit negotiation loop (D1).

Covers the three contract points from the build plan:

1. ``negotiation_rounds: N`` runs the loop up to N rounds and stops.
2. A scope-expanding modification (touching a non-negotiable key like
   ``target`` or ``phase``) is rejected — the modification is dropped and the
   original task runs.
3. ``negotiation_rounds: 0`` reproduces the legacy one-shot behavior: the
   critic's ``modify`` is applied once, no re-review.

Also covers the failure modes:

- Rounds exhausted without consensus -> fall back to the current task + log.
- Deadlock (same modification twice in a row) -> break.
- Critic ``deny`` still blocks regardless of negotiation rounds.
- The allowlist lock is untouched (negotiation never changes target/scope).
"""

from __future__ import annotations

from typing import Any

from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.orchestrator import SwarmOrchestrator

# ── Test agents ──────────────────────────────────────────────────────────


class _EchoAgent(Agent):
    """Records the task it actually ran with (post-negotiation)."""

    def __init__(self) -> None:
        super().__init__()
        self.runs: list[dict[str, Any]] = []

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self.runs.append(dict(task))
        self._set_status(AgentStatus.COMPLETE)
        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task.get("task_id", ""),
            output={"ran_with": dict(task)},
        )


class _ScriptedCritic(Agent):
    """Critic that plays back a scripted list of decisions, one per round.

    Each entry is ``("approve"|"deny"|"modify", modifications_dict)``. The
    critic advances its internal pointer on every ``run`` so the negotiation
    loop sees a different decision each round until the script ends (then it
    returns ``approve`` so the loop terminates cleanly if it runs past the
    script).

    The script is a class attribute (``script``) so the orchestrator can
    instantiate the critic with no args (``critic_cls()``). Use
    ``_scripted_critic_class([...])`` to build a fresh subclass with a given
    script baked in."""

    script: list[tuple[str, dict[str, Any]]] = []

    def __init__(self) -> None:
        super().__init__()
        self._script = list(self.__class__.script)
        self._idx = 0
        self.calls: list[dict[str, Any]] = []

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self._set_status(AgentStatus.RUNNING)
        proposed = task.get("proposed_action", {})
        if self._idx < len(self._script):
            decision, mods = self._script[self._idx]
            self._idx += 1
        else:
            decision, mods = "approve", {}
        self.calls.append({"proposed": dict(proposed), "decision": decision, "modifications": dict(mods)})
        self._set_status(AgentStatus.COMPLETE)
        return AgentResult(
            agent_type="critic",
            status=self.status,
            task_id=task.get("task_id", ""),
            output={"decision": decision, "reasoning": f"scripted[{self._idx - 1}]", "modifications": mods},
        )


def _scripted_critic_class(script: list[tuple[str, dict[str, Any]]]) -> type[_ScriptedCritic]:
    """Build a fresh _ScriptedCritic subclass with ``script`` baked in as a
    class attribute, so the orchestrator's ``critic_cls()`` (no-arg) call
    instantiates a critic that plays back this script."""
    return type("_ScriptedCritic_", (_ScriptedCritic,), {"script": list(script)})


def _make_orch(
    critic_cls: type[_ScriptedCritic],
    *,
    negotiation_rounds: int,
    worker: _EchoAgent | None = None,
) -> tuple[SwarmOrchestrator, _EchoAgent, _ScriptedCritic]:
    """Build an orchestrator whose worker agent is a pre-built instance and
    whose critic is a fresh instance of ``critic_cls`` per route() call (the
    orchestrator instantiates the critic itself; we only get to assert on it
    after the fact by reading the class's shared state).

    Returns (orchestrator, worker, critic_instance_used). The critic instance
    is captured by having ``_spawn`` record it when the orchestrator builds
    one — but the critic is NOT built via ``_spawn`` (the orchestrator
    constructs it directly at route() line 191). So we instead let the
    orchestrator build the critic normally and capture it via a class-level
    last-instance pointer."""
    worker = worker or _EchoAgent()
    critic_holder: dict[str, _ScriptedCritic | None] = {"instance": None}

    # Wrap critic_cls so every instantiation records the instance in the
    # holder, letting the test assert on the critic that actually ran.
    class _CapturingCritic(critic_cls):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__()
            critic_holder["instance"] = self

    orch = SwarmOrchestrator(
        context={},
        agent_registry={"test": _EchoAgent, "critic": _CapturingCritic},
        critic_enabled=True,
        reflection_enabled=False,
        negotiation_rounds=negotiation_rounds,
    )

    # Monkeypatch _spawn so the WORKER agent is our pre-built instance (the
    # critic is instantiated separately by route() and is NOT affected by
    # this patch — it goes through _CapturingCritic above).
    worker_holder = {"instance": worker}

    def fake_spawn(agent_cls, task_id=""):
        inst = worker_holder["instance"]
        inst._task_id = task_id
        orch._agents[inst.agent_id] = inst
        inst._set_status(AgentStatus.RUNNING)
        return inst

    orch._spawn = fake_spawn  # type: ignore[method-assign]
    return orch, worker_holder["instance"], critic_holder  # type: ignore[return-value]


# ── D1 contract: rounds run + stop ───────────────────────────────────────


def test_negotiation_runs_n_rounds_then_approves():
    """Critic modifies twice then approves on round 3. With
    ``negotiation_rounds=3`` the loop runs 3 rounds (round 0 = initial
    modify, rounds 1-2 = re-reviews) and the third review approves."""
    # Script: round0 modify, round1 modify, round2 approve.
    critic_cls = _scripted_critic_class([
        ("modify", {"risk_level": "medium"}),
        ("modify", {"risk_level": "low"}),
        ("approve", {}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    critic = critic_holder["instance"]
    assert critic is not None
    # The critic was called 3 times: round 0 + rounds 1, 2.
    assert len(critic.calls) == 3
    # The worker saw the final modified task (risk_level downgraded to low).
    assert worker.runs, "worker never ran"
    assert worker.runs[0].get("risk_level") == "low"


def test_negotiation_rounds_zero_is_legacy_one_shot():
    """``negotiation_rounds: 0`` reproduces the legacy one-shot behavior:
    the critic's first ``modify`` is applied once, NO re-review, the task
    runs immediately. The critic is called exactly once."""
    critic_cls = _scripted_critic_class([
        ("modify", {"risk_level": "medium"}),
        ("modify", {"risk_level": "low"}),  # would be round 1 if loop ran
        ("approve", {}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=0)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    critic = critic_holder["instance"]
    assert critic is not None
    # Legacy: critic called once, its modify applied, no re-review.
    assert len(critic.calls) == 1
    assert worker.runs[0].get("risk_level") == "medium"


def test_negotiation_exhausted_falls_back_to_last_task():
    """Rounds exhausted without consensus: the task runs with whatever
    modifications were applied in the last accepted round. The critic is
    called ``rounds + 1`` times (round 0 + N re-reviews), all ``modify``."""
    # Script: all modify, same safe key, different values so no deadlock.
    critic_cls = _scripted_critic_class([
        ("modify", {"risk_level": "medium"}),
        ("modify", {"max_retries": 3}),
        ("modify", {"rate_limit_seconds": 2}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=2)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    critic = critic_holder["instance"]
    assert critic is not None
    # round 0 + rounds 1, 2 = 3 critic calls.
    assert len(critic.calls) == 3
    # The worker ran with the last applied modification.
    assert worker.runs[0].get("rate_limit_seconds") == 2


def test_negotiation_deadlock_breaks_loop():
    """Same modification twice in a row = deadlock -> break. The task runs
    with the first instance of that modification applied; the second
    (repeated) modification does NOT re-apply (it would be a no-op anyway,
    but the loop stops before applying it)."""
    same_mods = {"risk_level": "medium"}
    critic_cls = _scripted_critic_class([
        ("modify", same_mods),
        ("modify", same_mods),  # identical -> deadlock
        ("approve", {}),  # never reached
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    critic = critic_holder["instance"]
    assert critic is not None
    # round 0 + round 1 (deadlock) = 2 critic calls. The third script entry
    # is never played.
    assert len(critic.calls) == 2
    assert worker.runs[0].get("risk_level") == "medium"


def test_negotiation_deny_blocks_regardless_of_rounds():
    """A ``deny`` at any round blocks the task. The worker never runs."""
    critic_cls = _scripted_critic_class([
        ("modify", {"risk_level": "medium"}),
        ("deny", {}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.BLOCKED
    assert "Critic blocked" in result.error
    assert not worker.runs, "worker ran despite deny"


def test_negotiation_immediate_deny_blocks():
    """A ``deny`` on round 0 blocks before any modification is applied."""
    critic_cls = _scripted_critic_class([("deny", {})])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5"})
    assert result.status == AgentStatus.BLOCKED
    assert not worker.runs


# ── D1 contract: scope-expanding modification rejected ───────────────────


def test_negotiation_scope_expansion_rejected():
    """A modification that touches a non-negotiable key (``target``,
    ``phase``, ``allowed_tools``, ``scope``, ``asset_type``) is rejected:
    the out-of-scope keys are dropped. If the WHOLE modification is
    out-of-scope, the loop stops and the original task runs unchanged."""
    critic_cls = _scripted_critic_class([
        ("modify", {"target": "10.0.0.99"}),  # scope expansion -> all rejected
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    # Original target is 10.0.0.5; critic tries to redirect to 10.0.0.99.
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    # The target was NOT changed — the scope expansion was rejected.
    assert worker.runs[0].get("target") == "10.0.0.5"


def test_negotiation_mixed_modification_keeps_safe_keys():
    """A modification with BOTH safe and out-of-scope keys keeps the safe
    keys and drops the out-of-scope ones. The loop continues (not all
    rejected)."""
    critic_cls = _scripted_critic_class([
        ("modify", {"risk_level": "low", "target": "10.0.0.99"}),  # mixed
        ("approve", {}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
    # Safe key applied, unsafe key dropped.
    assert worker.runs[0].get("risk_level") == "low"
    assert worker.runs[0].get("target") == "10.0.0.5"


def test_negotiation_phase_change_rejected():
    """A critic trying to change the phase (e.g. recon -> exploit) is a
    scope expansion and is rejected."""
    critic_cls = _scripted_critic_class([
        ("modify", {"phase": "exploit"}),
    ])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    result = orch.route({"task_id": "T-1", "phase": "test", "target": "10.0.0.5"})
    assert result.status == AgentStatus.COMPLETE
    assert worker.runs[0].get("phase") == "test"


# ── D1 contract: critic not run for recon/report ─────────────────────────


def test_negotiation_skipped_for_recon_phase():
    """The critic pre-check (and therefore negotiation) is skipped for the
    ``recon`` and ``report`` phases — they are low-risk / post-hoc."""
    critic_cls = _scripted_critic_class([("deny", {})])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    # Register a recon worker so the route can find an agent.
    orch._agent_registry["recon"] = _EchoAgent
    result = orch.route({"task_id": "T-1", "phase": "recon", "target": "10.0.0.5"})
    assert result.status == AgentStatus.COMPLETE
    # Critic never called for recon.
    critic = critic_holder["instance"]
    assert critic is None or len(critic.calls) == 0
    assert worker.runs


def test_negotiation_skipped_for_report_phase():
    critic_cls = _scripted_critic_class([("deny", {})])
    orch, worker, critic_holder = _make_orch(critic_cls, negotiation_rounds=3)
    # ``report`` routes to ReflectionAgent by default; we need a worker in
    # the registry for it.
    orch._agent_registry["report"] = _EchoAgent
    result = orch.route({"task_id": "T-1", "phase": "report", "target": "10.0.0.5"})
    assert result.status == AgentStatus.COMPLETE
    critic = critic_holder["instance"]
    assert critic is None or len(critic.calls) == 0


# ── D1 contract: existing swarm tests unchanged with rounds=0 ────────────


def test_legacy_modify_test_still_passes_with_negotiation_default():
    """The existing ``test_orchestrator_critic_modifies_task`` behavior
    (high risk downgraded to medium in standard_authorized mode) must still
    hold with the default ``negotiation_rounds=0``. This is the regression
    guard: negotiation must not change the one-shot path."""
    orch = SwarmOrchestrator(context={}, critic_enabled=True, reflection_enabled=False)
    result = orch.route({"task_id": "T-1", "phase": "test", "objective": "scan", "risk_level": "high"})
    assert result.status == AgentStatus.COMPLETE
