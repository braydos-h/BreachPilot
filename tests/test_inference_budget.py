"""Single inference budget: campaign x worker x swarm LLM-call ceiling.

Per-layer bounds already exist (campaign ``max_cycles`` / task ``max_retries`` /
worker ``attack_max_rounds`` / peer ``max_consultations``) but nothing ties them
together, so the product can multiply unboundedly. ``InferenceBudget`` is the
one object that threads the layers: construct it from config, share it, and
every retry/consultation path consumes from it.
"""

from __future__ import annotations

from tools.kernel.inference_budget import InferenceBudget


def test_unbounded_by_default():
    budget = InferenceBudget()
    assert budget.exhausted is False
    for _ in range(1000):
        assert budget.consume() is True
    assert budget.exhausted is False
    assert budget.remaining is None


def test_bounded_budget_exhausts():
    budget = InferenceBudget(max_calls=3)
    assert budget.consume() is True
    assert budget.consume() is True
    assert budget.consume() is True
    assert budget.exhausted is True
    assert budget.consume() is False
    assert budget.remaining == 0


def test_remaining_counts_down():
    budget = InferenceBudget(max_calls=5)
    assert budget.remaining == 5
    budget.consume()
    budget.consume()
    assert budget.remaining == 3
    assert budget.spent == 2


def test_from_config_disabled_by_default():
    budget = InferenceBudget.from_config({})
    assert budget.is_bounded is False
    assert budget.consume() is True


def test_from_config_reads_max_inference_calls():
    budget = InferenceBudget.from_config({"max_inference_calls": 2})
    assert budget.is_bounded is True
    assert budget.consume() is True
    assert budget.consume() is True
    assert budget.consume() is False


def test_from_config_tolerates_garbage():
    assert InferenceBudget.from_config(None).is_bounded is False
    assert InferenceBudget.from_config({"max_inference_calls": "bogus"}).is_bounded is False
    assert InferenceBudget.from_config({"max_inference_calls": -5}).is_bounded is False
    assert InferenceBudget.from_config({"max_inference_calls": 0}).is_bounded is False


def test_reset_restores_budget():
    budget = InferenceBudget(max_calls=1)
    assert budget.consume() is True
    assert budget.consume() is False
    budget.reset()
    assert budget.consume() is True
