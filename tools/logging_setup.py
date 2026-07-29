"""Centralized logging for the AI Bug Bounty Research Agent.

Writes to research_workspace/logs/app.log with rotation support.
Provides a consistent logging interface for CLI modes.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────────

DEFAULT_LOG_DIR = Path(os.environ.get("RESEARCH_WORKSPACE", "research_workspace")) / "logs"
DEFAULT_LOG_FILE = "app.log"
MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

# Global logger instance
_logger: logging.Logger | None = None


# ── Formatter ──────────────────────────────────────────────────────────────

class ColoredFormatter(logging.Formatter):
    """Formatter with ANSI colors for console output."""

    COLORS = {
        "DEBUG": "\x1b[36m",     # Cyan
        "INFO": "\x1b[32m",      # Green
        "WARNING": "\x1b[33m",   # Yellow
        "ERROR": "\x1b[31m",     # Red
        "CRITICAL": "\x1b[1;31m", # Bold Red
    }
    RESET = "\x1b[0m"

    def format(self, record: logging.LogRecord) -> str:
        if sys.stderr.isatty():
            color = self.COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


# ── Setup ──────────────────────────────────────────────────────────────────

def setup_logging(
    *,
    log_dir: Path | str | None = None,
    log_file: str = DEFAULT_LOG_FILE,
    level: int = logging.INFO,
    console: bool = True,
    file_output: bool = True,
) -> logging.Logger:
    """Configure and return the centralized logger.

    Args:
        log_dir: Directory for log files. Defaults to research_workspace/logs.
        log_file: Log file name.
        level: Minimum log level.
        console: Whether to output to stderr.
        file_output: Whether to output to file.

    Returns:
        The configured root logger for the application.
    """
    global _logger

    if log_dir is None:
        log_dir = DEFAULT_LOG_DIR

    logger = logging.getLogger("ai_bug_bounty")
    logger.setLevel(level)
    logger.handlers.clear()

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_formatter = ColoredFormatter(
            "[%(levelname)-22s] %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    log_path = Path(log_dir)
    file_logging_enabled = False

    # This function runs during MCP module imports. A stale or root-owned
    # workspace must not prevent either server transport from starting.
    if file_output:
        try:
            log_path.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_path / log_file,
                maxBytes=MAX_LOG_BYTES,
                backupCount=BACKUP_COUNT,
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning(
                "File logging disabled; cannot write to %s: %s",
                log_path,
                exc,
            )
        else:
            file_handler.setLevel(level)
            file_formatter = logging.Formatter(
                "%(asctime)s [%(levelname)-8s] %(name)s:%(funcName)s:%(lineno)d — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            file_logging_enabled = True

    _logger = logger
    if file_logging_enabled:
        logger.info("Logging initialized. Log file: %s", log_path / log_file)
    else:
        logger.info("Logging initialized without file output.")
    return logger


def get_logger() -> logging.Logger:
    """Get the centralized logger. Creates a default one if not set up."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


# ── Convenience functions ──────────────────────────────────────────────────

def log_info(msg: str, *args: Any) -> None:
    get_logger().info(msg, *args)


def log_warning(msg: str, *args: Any) -> None:
    get_logger().warning(msg, *args)


def log_error(msg: str, *args: Any) -> None:
    get_logger().error(msg, *args)


def log_debug(msg: str, *args: Any) -> None:
    get_logger().debug(msg, *args)


def log_critical(msg: str, *args: Any) -> None:
    get_logger().critical(msg, *args)


def log_exception(msg: str, *args: Any) -> None:
    get_logger().exception(msg, *args)
