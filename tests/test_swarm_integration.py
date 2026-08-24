"""Integration tests for swarm + semantic memory + adaptive exploits.

These tests verify that the new subsystems work together end-to-end
without requiring a live Ollama instance or MCP session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_loop import AgentLoop
from db import DatabaseManager
from tools.experience_store import ExperienceStore
from tools.exploit_mutator import ExploitMutator
from tools.payload_crafter import PayloadCrafter
from tools.semantic_memory import SemanticMemoryManager
from tools.swarm.orchestrator import SwarmOrchestrator


@pytest.fixture
def temp_db(tmp_path):
    # ponytail: previously a hardcoded test_workspace_integration/ path that
    # persisted across runs and accumulated stale rows, polluting later
    # tests (inflated confidence scores, UNIQUE-constraint collisions).
    # tmp_path is pytest-provided: unique per test, auto-cleaned.
    db_path = tmp_path / "research.db"
    db = DatabaseManager(db_path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    yield db


@pytest.fixture
def mock_executor():
    def _exec(tool: str, args: dict) -> str:
        return f"Mock output for {tool}"

    return _exec


# ── End-to-End Swarm + Memory Integration ────────────────────────────────


def test_agent_loop_with_swarm_and_semantic_memory(temp_db, mock_executor, tmp_path):
    """Run AgentLoop with swarm enabled and semantic memory active."""
    config = {
        "program_name": "Integration Test",
        "objective": "test swarm + memory",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "disallowed_assets": [],
        "forbidden_actions": [],
        "testing_modes": ["recon"],
        "use_swarm": True,
        "swarm_max_parallel": 2,
        "critic_enabled": True,
        "reflection_enabled": True,
        "reflection_every_n_actions": 2,
        "memory": {"semantic_enabled": True, "embedding_model": "nomic-embed-text"},
    }
    loop = AgentLoop(config, tmp_path, mock_executor)
    assert loop._use_swarm is True
    assert loop._swarm is not None
    assert loop._semantic_memory is not None
    assert loop._experience is not None


def test_swarm_orchestrator_routes_all_agent_types():
    """Verify the orchestrator can route to every specialist agent type."""

    orch = SwarmOrchestrator(
        context={},
        critic_enabled=False,
        reflection_enabled=False,
    )

    # Verify all default agents are registered (critic is internal, not routable by phase)
    assert "recon" in orch._agent_registry
    assert "analysis" in orch._agent_registry
    assert "test" in orch._agent_registry
    assert "exploit" in orch._agent_registry
    assert "post_exploit" in orch._agent_registry
    assert "report" in orch._agent_registry
    # Critic is used internally by orchestrator, not mapped to a phase
    assert "critic" not in orch._agent_registry


def test_experience_store_feedback_loop(temp_db):
    """Verify Bayesian confidence updates correctly across multiple outcomes."""
    store = ExperienceStore(temp_db)

    # Record mixed outcomes
    for _ in range(3):
        store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "success")
    for _ in range(2):
        store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "failure")
    store.record_outcome("ssh:8.2:linux", "SSHBruteForce", "partial")

    conf = store.get_confidence("ssh:8.2:linux", "SSHBruteForce")
    # Beta(1 + 3 + 0.5, 1 + 2 + 0.5) = Beta(4.5, 3.5) mean = 4.5/8 = 0.5625
    assert conf == pytest.approx(0.5625, abs=0.01)


def test_payload_crafter_generates_valid_python(temp_db):
    """Verify PayloadCrafter produces syntactically valid Python."""
    import ast

    crafter = PayloadCrafter(
        workspace=temp_db._path.parent / "mutations",
        experience_store=None,
        client=None,
        model="",
    )

    payload = crafter.generate(
        target_ip="10.0.0.1",
        service_name="http",
        version="nginx/1.18",
        os_hint="linux",
        module_name="BasicAuthBuster",
    )

    assert payload.script
    assert payload.generation_id.startswith("gen-")
    # Verify it's valid Python syntax
    try:
        ast.parse(payload.script)
    except SyntaxError:
        pytest.fail("Generated script is not valid Python")


def test_exploit_mutator_lineage_tracking(temp_db):
    """Verify mutation lineage is tracked correctly."""
    workspace = temp_db._path.parent / "mutations"
    mutator = ExploitMutator(
        workspace=workspace,
        experience_store=None,
        client=None,
        model="",
        max_mutations=3,
    )

    initial = mutator.craft_initial(
        target_ip="10.0.0.1",
        service_name="redis",
        version="6.0",
        os_hint="linux",
        module_name="RedisExploit",
    )

    mutated = mutator.mutate_on_failure(initial, "Connection refused", attempt_number=1)
    assert mutated is not None
    assert mutated.parent_id == initial.generation_id

    lineage = mutator.get_lineage(mutated.generation_id)
    assert len(lineage) == 2
    assert lineage[0]["generation_id"] == initial.generation_id
    assert lineage[1]["generation_id"] == mutated.generation_id


def test_semantic_memory_similarity_roundtrip(temp_db):
    """Verify embedding storage and cosine similarity retrieval."""
    mgr = SemanticMemoryManager(temp_db)
    # Mock embedding to avoid Ollama dependency
    mgr._generate_embedding = lambda text: [0.1 * (ord(c) % 10) for c in text[:10]]

    eid1 = mgr.store_embedding("memories", "MEM-001", "ssh brute force attempt", mission_id="M-001")
    eid2 = mgr.store_embedding("memories", "MEM-002", "ftp anonymous login test", mission_id="M-001")
    assert eid1 is not None
    assert eid2 is not None

    similar = mgr.find_similar("ssh attack", source_table="memories", top_k=2, mission_id="M-001")
    assert len(similar) == 2
    # "ssh attack" should be more similar to "ssh brute force attempt" than "ftp anonymous login test"
    assert similar[0]["source_id"] == "MEM-001"


# ── Config Integration ───────────────────────────────────────────────────


def test_config_yaml_has_new_sections():
    """Verify config.yaml contains all new configuration sections."""
    import yaml

    config_path = Path("config.yaml")
    assert config_path.exists()
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert "swarm" in config
    assert "reasoning" in config
    assert "memory" in config
    assert "adaptive_exploits" in config

    assert config["swarm"].get("enabled") is True
    assert "agents" in config["swarm"]
    assert config["swarm"].get("max_parallel_agents") == 3

    assert config["reasoning"].get("chain_of_thought") is True
    assert config["reasoning"].get("critic_enabled") is True

    assert config["memory"].get("semantic_enabled") is True
    assert config["memory"].get("embedding_model") == "nomic-embed-text"

    assert config["adaptive_exploits"].get("enabled") is True
    assert config["adaptive_exploits"].get("max_mutations") == 5


# ── CLI Flags Integration ──────────────────────────────────────────────────


def test_main_cli_parses_new_flags():
    """Verify main.py parse_args handles all new CLI flags."""
    from main import parse_args

    args = parse_args(
        [
            "--target",
            "10.0.0.1",
            "--mode",
            "attack",
            "--swarm",
            "--critic",
            "--reflection",
            "--adaptive-exploits",
            "--observer-mode",
            "llm",
        ]
    )
    assert args.swarm is True
    assert args.critic is True
    assert args.reflection is True
    assert args.adaptive_exploits is True
    assert args.observer_mode == "llm"
