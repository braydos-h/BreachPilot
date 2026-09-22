"""P1-05: opencode_go provider must reuse a single persistent HTTP client."""

from __future__ import annotations

import httpx


def test_opencodego_reuses_single_client():
    from tools.providers import opencode_go_provider as og

    made: list[int] = []
    real = httpx.Client

    class Spy(real):
        def __init__(self, *a, **k):
            made.append(1)
            super().__init__(*a, **k)

    real_client_cls = og.httpx.Client
    og.httpx.Client = Spy  # type: ignore[attr-defined]
    try:
        c = og.OpenCodeGoResponsesClient(base_url="http://127.0.0.1:9", api_key="test-key", timeout=1)
        for _ in range(3):
            try:
                c.chat(model="m", messages=[{"role": "user", "content": "hi"}])
            except Exception:  # noqa: BLE001 -- refused loopback port is the point (no server)
                pass
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    finally:
        og.httpx.Client = real_client_cls  # type: ignore[attr-defined]
    assert len(made) == 1, f"built {len(made)} clients for 3 calls"


def test_opencodego_double_close_safe():
    from tools.providers import opencode_go_provider as og

    c = og.OpenCodeGoResponsesClient(base_url="http://127.0.0.1:9", api_key="test-key", timeout=1)
    c.close()
    c.close()  # must not raise
    with og.OpenCodeGoResponsesClient(base_url="http://127.0.0.1:9", api_key="test-key", timeout=1) as ctx:
        ctx.close()
