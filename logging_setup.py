"""Centralized structured logging for the analyzer.

Replaces ad-hoc print() calls with a stdlib logging configuration that
supports file output, JSON formatting, and color suppression (D1).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

_LOGGER_NAME = "github_actions_checks"

_RESERVED_LOG_KEYS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime",
}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOG_KEYS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class _ColorFormatter(logging.Formatter):
    _COLORS = {
        logging.DEBUG: "\033[37m",
        logging.INFO: "\033[36m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{self._RESET}" if color else message


_configured = False


def configure_logging(
    *,
    level: int = logging.INFO,
    json_format: bool = False,
    log_file: str | None = None,
    no_color: bool = False,
) -> None:
    """Configure the package-wide logger exactly once."""
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if _configured:
        logger.setLevel(level)
        return

    logger.setLevel(level)
    logger.propagate = False

    formatter: logging.Formatter
    if json_format:
        formatter = _JsonFormatter()
    else:
        formatter = _ColorFormatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ) if not no_color and _supports_color() else logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            _JsonFormatter() if json_format else formatter
        )
        logger.addHandler(file_handler)

    _configured = True


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
