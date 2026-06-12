"""CLI-level tests for the run-state and monitor subcommands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from resilient_updates.cli import main

CFG = "tests/fixtures/feed_sources.example.yaml"


def _run(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["cli", "--config", CFG, *argv])
    code = main()
    return code, capsys.readouterr().out


def test_run_state_begin_and_show(tmp_path: Path, monkeypatch, capsys):
    code, out = _run(
        monkeypatch,
        capsys,
        "run-state",
        "begin",
        "--artifacts-dir",
        str(tmp_path),
        "--target",
        "/data/app.tar.gz",
        "--case-id",
        "CYBERSEC-1",
    )
    assert code == 0
    body = json.loads(out)
    assert body["status"] == "ok"
    assert body["resumed"] is False
    assert body["completed"] == []

    code, out = _run(monkeypatch, capsys, "run-state", "show", "--artifacts-dir", str(tmp_path))
    assert code == 0
    shown = json.loads(out)
    assert shown["present"] is True
    assert shown["case_id"] == "CYBERSEC-1"


def test_run_state_stage_flow_and_should_skip(tmp_path: Path, monkeypatch, capsys):
    common = ["--artifacts-dir", str(tmp_path), "--target", "/data/app.tar.gz"]
    _run(monkeypatch, capsys, "run-state", "begin", *common)
    _run(monkeypatch, capsys, "run-state", "stage-start", "--stage", "extract", *common)
    _run(
        monkeypatch,
        capsys,
        "run-state",
        "stage-end",
        "--stage",
        "extract",
        "--ok",
        "true",
        "--rc",
        "0",
        *common,
    )

    code, out = _run(monkeypatch, capsys, "run-state", "should-skip", "--stage", "extract", *common)
    assert code == 0
    assert json.loads(out)["skip"] is True

    code, out = _run(monkeypatch, capsys, "run-state", "should-skip", "--stage", "sbom", *common)
    assert code == 1
    assert json.loads(out)["skip"] is False

    # A different target must never skip.
    code, _ = _run(
        monkeypatch,
        capsys,
        "run-state",
        "should-skip",
        "--stage",
        "extract",
        "--artifacts-dir",
        str(tmp_path),
        "--target",
        "/data/OTHER.tar.gz",
    )
    assert code == 1


def test_run_state_should_skip_requires_stage(tmp_path: Path, monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "run-state", "should-skip", "--artifacts-dir", str(tmp_path))
    assert code != 0
    assert "stage" in json.loads(out)["error"]


def test_run_state_finish(tmp_path: Path, monkeypatch, capsys):
    common = ["--artifacts-dir", str(tmp_path), "--target", "/t"]
    _run(monkeypatch, capsys, "run-state", "begin", *common)
    code, _ = _run(
        monkeypatch, capsys, "run-state", "finish", "--status", "error", "--artifacts-dir", str(tmp_path)
    )
    assert code == 0
    code, out = _run(monkeypatch, capsys, "run-state", "show", "--artifacts-dir", str(tmp_path))
    assert json.loads(out)["status"] == "error"


def test_monitor_json_once(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(
        "resilient_updates.monitor.list_containers",
        lambda root: {"ok": False, "error": "docker not found on PATH", "containers": []},
    )
    code, out = _run(monkeypatch, capsys, "monitor", "--json", "--artifacts-dir", str(tmp_path))
    assert code == 0
    body = json.loads(out)
    assert body["pipeline"] == {"present": False}
    assert body["containers"]["ok"] is False


def test_monitor_text_once(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(
        "resilient_updates.monitor.list_containers",
        lambda root: {"ok": True, "containers": []},
    )
    code, out = _run(monkeypatch, capsys, "monitor", "--artifacts-dir", str(tmp_path))
    assert code == 0
    assert "Пайплайн" in out


@pytest.mark.parametrize("action", ["stage-start", "stage-end", "stage-skip"])
def test_run_state_stage_actions_require_stage(tmp_path: Path, monkeypatch, capsys, action):
    code, out = _run(monkeypatch, capsys, "run-state", action, "--artifacts-dir", str(tmp_path))
    assert code != 0
    assert "stage" in json.loads(out)["error"]
