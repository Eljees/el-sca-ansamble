"""Tests for resilient_updates.dashboard (ADR-0006 P1, read-only JSON API).

Pure-helper tests run everywhere; the TestClient endpoint tests skip cleanly
when fastapi / httpx are not installed, so the suite stays green on hosts that
have not yet regenerated requirements with the web dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.dashboard import list_runs, render_index, render_run, run_detail


def _populate(artifacts: Path) -> None:
    (artifacts / "provenance").mkdir(parents=True)
    (artifacts / "provenance" / "trivy.json").write_text(
        json.dumps({"tool": "trivy", "activation_status": "ok"}), encoding="utf-8"
    )
    (artifacts / "MANIFEST.json").write_text(json.dumps({"run_id": "r1"}), encoding="utf-8")
    (artifacts / "reports" / "final").mkdir(parents=True)
    (artifacts / "reports" / "final" / "report.md").write_text("# report", encoding="utf-8")


# --- pure helpers -----------------------------------------------------------


def test_list_runs_empty(tmp_path: Path):
    assert list_runs(tmp_path) == []


def test_list_runs_populated(tmp_path: Path):
    _populate(tmp_path)
    runs = list_runs(tmp_path)
    assert len(runs) == 1
    assert runs[0]["id"] == "current"
    assert runs[0]["manifest_present"] is True
    assert "trivy" in runs[0]["provenance_tools"]
    assert runs[0]["report_count"] == 1


def test_run_detail_current_and_unknown(tmp_path: Path):
    _populate(tmp_path)
    detail = run_detail(tmp_path, "current")
    assert detail is not None
    assert detail["provenance"]["trivy"]["tool"] == "trivy"
    assert detail["manifest"]["run_id"] == "r1"
    assert run_detail(tmp_path, "bogus") is None


# --- endpoints (skip when fastapi/httpx absent) -----------------------------


def _client(artifacts: Path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from resilient_updates.dashboard import create_app

    return TestClient(create_app(artifacts))


def test_healthz(tmp_path: Path):
    resp = _client(tmp_path).get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_api_runs_populated(tmp_path: Path):
    _populate(tmp_path)
    resp = _client(tmp_path).get("/api/runs")
    assert resp.status_code == 200
    assert resp.json()["runs"][0]["id"] == "current"


def test_api_run_detail_and_404(tmp_path: Path):
    _populate(tmp_path)
    client = _client(tmp_path)
    assert client.get("/api/runs/current").json()["provenance"]["trivy"]["tool"] == "trivy"
    assert client.get("/api/runs/bogus").status_code == 404


def test_api_freshness_shape(tmp_path: Path):
    resp = _client(tmp_path).get("/api/freshness")
    assert resp.status_code == 200
    body = resp.json()
    assert "should_fail" in body and "on_stale" in body


# --- HTML rendering (P2) ----------------------------------------------------


def test_render_index_empty_and_populated(tmp_path: Path):
    assert "No runs yet" in render_index(tmp_path)
    _populate(tmp_path)
    html = render_index(tmp_path)
    assert "<h1>Runs</h1>" in html
    assert "/runs/current" in html


def test_render_run_unknown_is_none(tmp_path: Path):
    _populate(tmp_path)
    assert render_run(tmp_path, "bogus") is None
    assert "trivy" in render_run(tmp_path, "current")


def test_html_index_and_run_page(tmp_path: Path):
    _populate(tmp_path)
    client = _client(tmp_path)
    index = client.get("/")
    assert index.status_code == 200
    assert "text/html" in index.headers["content-type"]
    assert "Runs" in index.text
    run = client.get("/runs/current")
    assert run.status_code == 200
    assert "trivy" in run.text
    assert client.get("/runs/bogus").status_code == 404
