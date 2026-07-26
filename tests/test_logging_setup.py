from __future__ import annotations

import logging
from pathlib import Path


def test_get_logger_survives_unwritable_default_log_directory(
    monkeypatch,
    capsys,
) -> None:
    """Import-time logging must not prevent the MCP server from starting."""
    from tools import logging_setup

    application_logger = logging.getLogger("ai_bug_bounty")
    original_handlers = application_logger.handlers[:]
    monkeypatch.setattr(logging_setup, "_logger", None)

    def deny_log_directory(
        self: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "mkdir", deny_log_directory)

    try:
        logger = logging_setup.get_logger()

        assert logger.name == "ai_bug_bounty"
        assert "File logging disabled" in capsys.readouterr().err
    finally:
        for handler in application_logger.handlers:
            if handler not in original_handlers:
                handler.close()
        application_logger.handlers[:] = original_handlers
