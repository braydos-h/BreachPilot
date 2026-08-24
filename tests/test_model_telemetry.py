from __future__ import annotations

from pathlib import Path

from tools.model_telemetry import build_usage_record, estimate_context_tokens, read_usage_records


def test_usage_record_extracts_ollama_token_and_duration_fields() -> None:
    response = {
        "message": {"content": "not persisted by telemetry"},
        "prompt_eval_count": 12,
        "eval_count": 30,
        "prompt_eval_duration": 1_500_000_000,
        "eval_duration": 3_000_000_000,
        "total_duration": 5_000_000_000,
    }
    messages = [
        {"role": "system", "content": "You are concise."},
        {"role": "user", "content": "Summarize the target."},
    ]

    record = build_usage_record(
        alias="glm",
        model_id="glm-5.2:cloud",
        response=response,
        messages=messages,
        stream=False,
        started_at="2026-06-18T00:00:00+00:00",
        ended_at="2026-06-18T00:00:05+00:00",
        wall_duration_seconds=5.0,
        context_window_tokens=1000,
        source="test",
    )

    assert record["prompt_tokens"] == 12
    assert record["completion_tokens"] == 30
    assert record["total_tokens"] == 42
    assert record["provider_total_duration_seconds"] == 5.0
    assert record["prompt_tokens_per_second"] == 8.0
    assert record["completion_tokens_per_second"] == 10.0
    assert record["tokens_per_second"] == 8.4
    assert record["estimated_context_tokens"] == estimate_context_tokens(messages)
    assert record["context_usage_pct"] == record["estimated_context_tokens"] / 1000 * 100
    assert "content" not in record


def test_usage_record_handles_missing_provider_usage_fields() -> None:
    record = build_usage_record(
        alias="custom",
        model_id="custom-model",
        response={"message": {"content": "hello"}},
        messages=[{"role": "user", "content": "hello"}],
        stream=False,
        started_at="2026-06-18T00:00:00+00:00",
        ended_at="2026-06-18T00:00:01+00:00",
        wall_duration_seconds=1.0,
        context_window_tokens=None,
        source="test",
    )

    assert record["prompt_tokens"] is None
    assert record["completion_tokens"] is None
    assert record["total_tokens"] is None
    assert record["tokens_per_second"] is None
    assert record["context_window_tokens"] is None
    assert record["context_usage_pct"] is None


def test_model_router_records_usage_for_chat_call_styles(tmp_path: Path, monkeypatch) -> None:
    import tools.model_router as model_router

    class FakeOllamaClient:
        def __init__(self, host: str) -> None:
            self.host = host

        def list(self) -> dict:
            return {}

        def chat(self, model: str, **kwargs):
            assert model == "glm-5.2:cloud"
            if kwargs.get("stream"):

                def chunks():
                    yield {"message": {"content": "hi"}}
                    yield {
                        "message": {"content": ""},
                        "prompt_eval_count": 2,
                        "eval_count": 4,
                        "eval_duration": 2_000_000_000,
                    }

                return chunks()
            return {
                "message": {"content": "ok"},
                "prompt_eval_count": 3,
                "eval_count": 5,
                "eval_duration": 1_000_000_000,
            }

    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path))
    monkeypatch.setattr(model_router, "OllamaClient", FakeOllamaClient)

    client = model_router._build_model_client("glm-5.2:cloud", alias="glm")
    client.chat("glm", messages=[{"role": "user", "content": "one"}], stream=False)
    client.chat(messages=[{"role": "user", "content": "two"}], stream=False)
    list(client.chat("glm", messages=[{"role": "user", "content": "three"}], stream=True))

    records = read_usage_records(tmp_path, limit=10)

    assert len(records) == 3
    assert {record["alias"] for record in records} == {"glm"}
    assert records[0]["stream"] is True
    assert records[0]["completion_tokens_per_second"] == 2.0
    assert records[1]["completion_tokens"] == 5
