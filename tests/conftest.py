"""Shared fixtures — ponytail: replace copy-paste Mock(spec=...) across 249 tests.

These three fixtures cover the most duplicated mocks (grep "Mock(spec=" shows
>80 sites for MCP session / Ollama client / Nmap). New tests should use them
instead of hand-rolling Mocks. Existing tests are migrated incrementally — the
fixtures are opt-in, never breaking.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock


@pytest.fixture
def mock_mcp_session():
    """Mocked MCP ClientSession (stdio_client/streamable_http_client)."""
    session = AsyncMock()
    session.initialize = AsyncMock(return_value=None)
    session.list_tools = AsyncMock(return_value=[])
    session.call_tool = AsyncMock(return_value=Mock(content=[Mock(text="ok")], isError=False))
    return session


@pytest.fixture
def mock_ollama():
    """Mocked Ollama client (model_router.build_router → get_client → chat)."""
    client = Mock()
    client.chat = Mock(return_value={"message": {"content": "ok"}})
    client.generate = Mock(return_value={"response": "ok"})
    router = Mock()
    router.get_client.return_value = client
    return router


@pytest.fixture
def mock_nmap(tmp_path):
    """Mocked nmap subprocess output + recon_pipeline helpers."""
    nmap_mock = Mock()
    nmap_mock.run = Mock(return_value=Mock(stdout="<nmaprun/>", stderr="", returncode=0))
    return nmap_mock
