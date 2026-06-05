"""Centralized logging setup for resilient_updates.

Convention enforced by the audit (docs/audit/20-architecture.md section 3):

- Business logic uses ``logging.getLogger(__name__)`` and never prints.
- ``cli.py`` is the only module allowed to print to stdout, and only for
  command output (JSON payloads, table rows that the user piped into
  ``jq`` or ``column``).  Diagnostics go through the logger.

Environment knobs picked up by :func:`setup_logging`:

- ``LOG_LEVEL`` (default ``INFO``) - any value ``logging`` accepts.
- ``LOG_FORMAT`` (default ``text``) - either ``text`` or ``json``.

The function is idempotent: re-calling it on an already-configured root
logger is a no-op so unit tests can call it freely.
"""

from __future__ import annotations

import json
import logging
import os
import sys

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from typing import Any, ClassVar

_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


class JsonFormatter(logging.Formatter):
    """One JSON object per log record, single line, UTF-8 safe.

    Fields:

    - ``ts``     ISO-8601 UTC timestamp
    - ``level``  string ("INFO", "ERROR", ...)
    - ``logger`` logger name (usually the module path)
    - ``msg``    rendered message string
    - ``extra``  any ``logger.info(..., extra={...})`` payload, merged
    - ``exc``    full traceback string if ``exc_info`` was supplied
    """

    _RESERVED: ClassVar[set[str]] = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "asctime",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = {
            k: v for k, v in record.__dict__.items() if k not in self._RESERVED and not k.startswith("_")
        }
        if extra:
            payload["extra"] = extra
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(
    level: str | None = None,
    format: str | None = None,
    stream=None,
) -> None:
    """Configure the root logger.  Idempotent.

    Parameters override env vars; both default to environment lookup.
    """
    chosen_level = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    chosen_format = (format or os.environ.get("LOG_FORMAT") or "text").lower()
    chosen_stream = stream or sys.stderr

    root = logging.getLogger()
    # Idempotency guard: if a handler with our sentinel attribute is already
    # attached, refresh level only and skip the rest.  This keeps repeated
    # cli.main() calls during tests from stacking handlers.
    for handler in root.handlers:
        if getattr(handler, "_resilient_updates_sentinel", False):
            root.setLevel(_LEVELS.get(chosen_level, logging.INFO))
            return

    handler = logging.StreamHandler(chosen_stream)
    if chosen_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    handler._resilient_updates_sentinel = True
    root.addHandler(handler)
    root.setLevel(_LEVELS.get(chosen_level, logging.INFO))


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper so callers can avoid importing ``logging``."""
    return logging.getLogger(name)
