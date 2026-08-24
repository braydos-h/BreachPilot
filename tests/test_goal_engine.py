"""Tests for the goal engine."""

from tools.goal_engine import PRESET_GOALS, AttackGoal, GoalEngine


def test_preset_goals_exist():
    assert "backdoor" in PRESET_GOALS
    assert "initial_access" in PRESET_GOALS
    assert "recon_only" in PRESET_GOALS


def test_goal_engine_list_presets():
    engine = GoalEngine()
    presets = engine.list_presets()
    assert len(presets) == len(PRESET_GOALS)
    names = {p[0] for p in presets}
    assert "backdoor" in names


def test_get_preset_goal():
    engine = GoalEngine()
    goal = engine.get("backdoor")
    assert goal.name == "backdoor"
    assert "backdoor" in goal.description.lower()
    assert not goal.user_custom


def test_get_custom_goal():
    engine = GoalEngine()
    goal = engine.get("custom", "Steal the database")
    assert goal.name == "custom"
    assert goal.description == "Steal the database"
    assert goal.user_custom


def test_system_prompt_addition():
    goal = AttackGoal(name="test", description="A test goal")
    prompt = goal.system_prompt_addition()
    assert "PRIMARY MISSION" in prompt
    assert "test" in prompt
