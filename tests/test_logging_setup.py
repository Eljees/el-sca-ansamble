"""Tests for resilient_updates._logging."""
from __future__ import annotations

import io
import json
import logging
import os

import pytest

from resilient_updates._logging import JsonFormatter, setup_logging


def _reset_root_logger() -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)


@pytest.mark.smoke
def test_setup_logging_text_format_emits_one_line(monkeypatch) -> None:
    _reset_root_logger()
    buf = io.StringIO()
    setup_logging(level="DEBUG", format="text", stream=buf)
    logging.getLogger("t").info("hello")
    output = buf.getvalue()
    assert "INFO" in output
    assert "hello" in output


def test_setup_logging_json_format_is_valid_json(monkeypatch) -> None:
    _reset_root_logger()
    buf = io.StringIO()
    setup_logging(level="INFO", format="json", stream=buf)
    logging.getLogger("t.module").info("msg", extra={"run_id": "abc"})
    line = buf.getvalue().strip()
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "t.module"
    assert payload["msg"] == "msg"
    assert payload["extra"]["run_id"] == "abc"


def test_json_formatter_includes_traceback() -> None:
    _reset_root_logger()
    buf = io.StringIO()
    setup_logging(format="json", stream=buf)
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("t").exception("oops")
    payload = json.loads(buf.getvalue().strip())
    assert "ValueError" in payload["exc"]
    assert "boom" in payload["exc"]


def test_setup_is_idempotent_no_handler_stacking() -> None:
    _reset_root_logger()
    buf = io.StringIO()
    setup_logging(format="text", stream=buf)
    setup_logging(format="text", stream=buf)
    setup_logging(format="text", stream=buf)
    logging.getLogger("t").info("once")
    output = buf.getvalue()
    # Without idempotency, message would appear thrice.
    assert output.count("once") == 1


def test_setup_reads_env_when_args_not_passed(monkeypatch) -> None:
    _reset_root_logger()
    monkeypatch.setenv("LOG_FORMAT", "json")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    buf = io.StringIO()
    setup_logging(stream=buf)
    logging.getLogger("t").info("should-be-suppressed")
    logging.getLogger("t").warning("should-pass")
    output = buf.getvalue()
    assert "should-be-suppressed" not in output
    assert "should-pass" in output
