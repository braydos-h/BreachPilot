"""P1-04: chatgpt provider must reuse a single persistent HTTP client."""

from __future__ import annotations

import httpx


def test_chatgpt_reuses_single_client():
    from tools.providers import chatgpt_provider as cp

    made: list[int] = []
    real = httpx.Client

    class Spy(real):
        def __init__(self, *a, **k):
            made.append(1)
            super().__init__(*a, **k)

    real_client_cls = cp.httpx.Client
    cp.httpx.Client = Spy  # type: ignore[attr-defined]
    try:
        c = cp.ChatGptProxyClient("http://127.0.0.1:9/v1", timeout=1)
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
        cp.httpx.Client = real_client_cls  # type: ignore[attr-defined]
    assert len(made) == 1, f"built {len(made)} clients for 3 calls"


def test_chatgpt_double_close_safe():
    from tools.providers import chatgpt_provider as cp

    c = cp.ChatGptProxyClient("http://127.0.0.1:9/v1", timeout=1)
    c.close()
    c.close()  # must not raise
    with cp.ChatGptProxyClient("http://127.0.0.1:9/v1", timeout=1) as ctx:
        ctx.close()
