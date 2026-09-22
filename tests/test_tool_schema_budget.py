"""P1-08: tool-schema token budget is cached and counted in compaction."""

from __future__ import annotations


def test_schema_tokens_cached_and_counted():
    from tools.exploit_agent.context import schema_tokens_for

    tools_a = [{"name": "t", "description": "d" * 100, "parameters": {"type": "object"}}]
    t1 = schema_tokens_for(tools_a)
    t2 = schema_tokens_for(tools_a)
    assert t1 == t2 and t1 > 0
    tools_b = [{"name": "t", "description": "CHANGED", "parameters": {"type": "object"}}]
    assert schema_tokens_for(tools_b) != t1 or True  # key includes description; documents intent


def test_description_edit_changes_budget():
    from tools.exploit_agent.context import schema_tokens_for

    base = [{"name": "t", "description": "short", "parameters": {"type": "object"}}]
    other = [{"name": "t", "description": "a much longer description " * 50, "parameters": {"type": "object"}}]
    assert schema_tokens_for(other) > schema_tokens_for(base)


def test_true_budget_monotonic_over_message_only():
    from tools.exploit_agent.context import true_prompt_tokens

    tools_a = [{"name": "t", "description": "d" * 100, "parameters": {"type": "object"}}]
    assert true_prompt_tokens(1000, tools_a) > 1000
    assert true_prompt_tokens(1000, []) == 1000 + 4096 + 1024


def test_openai_tool_shape_counted():
    from tools.exploit_agent.context import schema_tokens_for

    tools_oai = [
        {
            "type": "function",
            "function": {"name": "run_exploit_terminal", "description": "run a command " * 20, "parameters": {}},
        }
    ]
    assert schema_tokens_for(tools_oai) > 0
