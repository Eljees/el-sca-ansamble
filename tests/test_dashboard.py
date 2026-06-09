"""Tests for resilient_updates.dashboard (ADR-0006 P1, read-only JSON API).

Pure-helper tests run everywhere; the TestClient endpoint tests skip cleanly
when fastapi / httpx are not installed, so the suite stays green on hosts that
have not yet regenerated requirements with the web dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.dashboard import (
    list_runs,
    render_index,
    render_run,
    run_detail,
    tool_status,
)


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
    # The active GUI now lives at "/"; the legacy run browser moved to "/runs".
    assert "Runs" in index.text
    assert client.get("/runs").status_code == 200
    run = client.get("/runs/current")
    assert run.status_code == 200
    assert "trivy" in run.text
    assert client.get("/runs/bogus").status_code == 404


# --- active GUI: tool status + endpoints (ADR-0008) -------------------------


def _populate_provenance(artifacts: Path) -> None:
    pdir = artifacts / "provenance"
    pdir.mkdir(parents=True)
    (pdir / "grype.json").write_text(
        json.dumps(
            {"activation_status": "active", "built": "2026-06-04T07:57:06Z", "checksum": "sha256:deadbeef"}
        ),
        encoding="utf-8",
    )
    (pdir / "trivy.json").write_text(json.dumps({"activation_status": "healthcheck-only"}), encoding="utf-8")
    (pdir / "cve-bin-tool-db.json").write_text(
        json.dumps(
            {
                "activation_status": "fresh",
                "selected_audit": {
                    "counts": {"cve_range_total": 1480394},
                    "files": {"cve.db": {"mtime_utc": "2026-06-02T23:50:01+00:00"}},
                },
            }
        ),
        encoding="utf-8",
    )


def test_tool_status_reports_versions_and_freshness(tmp_path: Path):
    _populate_provenance(tmp_path)
    data = tool_status(tmp_path, repo_root=tmp_path.parent)
    assert data["db_update_enabled_by_default"] is False
    by_name = {t["name"]: t for t in data["tools"]}
    assert {"Syft", "Grype", "Trivy", "cve-bin-tool"} <= set(by_name)
    # Engine versions fall back to compose defaults when no .env present.
    assert by_name["Grype"]["version"].startswith("v0.112")
    assert by_name["Trivy"]["version"] == "0.64.1"
    # DB freshness picked up from provenance.
    assert by_name["Grype"]["db_status"] == "active"
    assert by_name["Grype"]["db_updated"] == "2026-06-04T07:57:06Z"
    assert by_name["cve-bin-tool"]["db_status"] == "fresh"
    assert by_name["cve-bin-tool"]["db_updated"] == "2026-06-02T23:50:01+00:00"


def test_env_version_override(tmp_path: Path):
    _populate_provenance(tmp_path)
    (tmp_path.parent / ".env").write_text("GRYPE_VERSION=v9.9.9\n", encoding="utf-8")
    data = tool_status(tmp_path, repo_root=tmp_path.parent)
    grype = next(t for t in data["tools"] if t["name"] == "Grype")
    assert grype["version"] == "v9.9.9"


def test_api_tools_endpoint(tmp_path: Path):
    _populate_provenance(tmp_path)
    resp = _client(tmp_path).get("/api/tools")
    assert resp.status_code == 200
    body = resp.json()
    assert body["db_update_enabled_by_default"] is False
    assert any(t["name"] == "cve-bin-tool" for t in body["tools"])


def test_job_unknown_is_404(tmp_path: Path):
    client = _client(tmp_path)
    assert client.get("/api/jobs/nope").status_code == 404
    assert client.get("/api/jobs/nope/stream").status_code == 404


# ---------------------------------------------------------------------------
# POST /api/scan — file upload and tools parsing
# ---------------------------------------------------------------------------


def _mock_registry(monkeypatch, tmp_path):
    """Patch JobRegistry so start_scan/start_update never spawn subprocesses."""
    pytest.importorskip("fastapi")
    from resilient_updates.orchestrator import SCAN_STAGES, UPDATE_STAGES, Job, JobRegistry

    def fake_start_scan(self, target_host, tools=None):
        job = Job("scan", SCAN_STAGES, target=target_host)
        with self._lock:
            self._jobs[job.id] = job
        job.status = "done"
        return job

    def fake_start_update(self, target="all"):
        job = Job("update", UPDATE_STAGES)
        with self._lock:
            self._jobs[job.id] = job
        job.target = target
        job.status = "done"
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    monkeypatch.setattr(JobRegistry, "start_update", fake_start_update)
    return _client(tmp_path)


def test_api_scan_returns_job_id(tmp_path: Path, monkeypatch):
    client = _mock_registry(monkeypatch, tmp_path)
    import io

    resp = client.post(
        "/api/scan",
        files={"file": ("app.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
        data={"tools": "syft"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "job_id" in body
    assert "target" in body


def test_api_scan_empty_tools_selects_all(tmp_path: Path, monkeypatch):
    """tools='' must pass selected=None to start_scan (meaning run all tools)."""
    pytest.importorskip("fastapi")
    from resilient_updates.orchestrator import SCAN_STAGES, Job, JobRegistry

    captured: list = []

    def fake_start_scan(self, target_host, tools=None):
        captured.append(tools)
        job = Job("scan", SCAN_STAGES, target=target_host)
        with self._lock:
            self._jobs[job.id] = job
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    import io

    _client(tmp_path).post(
        "/api/scan",
        files={"file": ("a.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
        data={"tools": ""},
    )
    assert captured[0] is None


def test_api_scan_sparse_tools_string(tmp_path: Path, monkeypatch):
    """tools='syft,,grype' with extra commas must yield {'syft', 'grype'}."""
    pytest.importorskip("fastapi")
    from resilient_updates.orchestrator import SCAN_STAGES, Job, JobRegistry

    captured: list = []

    def fake_start_scan(self, target_host, tools=None):
        captured.append(tools)
        job = Job("scan", SCAN_STAGES, target=target_host)
        with self._lock:
            self._jobs[job.id] = job
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    import io

    _client(tmp_path).post(
        "/api/scan",
        files={"file": ("a.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
        data={"tools": "syft,,grype"},
    )
    assert captured[0] == {"syft", "grype"}


# ---------------------------------------------------------------------------
# POST /api/update-db — job creation
# ---------------------------------------------------------------------------


def test_api_update_db_default_target(tmp_path: Path, monkeypatch):
    client = _mock_registry(monkeypatch, tmp_path)
    resp = client.post("/api/update-db")
    assert resp.status_code == 200
    body = resp.json()
    assert "job_id" in body
    assert body["target"] == "all"


def test_api_update_db_specific_target(tmp_path: Path, monkeypatch):
    client = _mock_registry(monkeypatch, tmp_path)
    resp = client.post("/api/update-db?target=trivy")
    assert resp.status_code == 200
    assert resp.json()["target"] == "trivy"


def test_api_update_db_log_path_none(tmp_path: Path, monkeypatch):
    """When log_path is None the response contains an empty string for 'log'."""
    client = _mock_registry(monkeypatch, tmp_path)
    resp = client.post("/api/update-db")
    assert resp.json()["log"] == ""


# ---------------------------------------------------------------------------
# GET /api/jobs/{job_id} and /stream — job status + SSE
# ---------------------------------------------------------------------------


def test_api_job_status_after_update(tmp_path: Path, monkeypatch):
    """After start_update, /api/jobs/{id} must return the job snapshot."""
    client = _mock_registry(monkeypatch, tmp_path)
    job_id = client.post("/api/update-db").json()["job_id"]
    resp = client.get(f"/api/jobs/{job_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == job_id
    assert body["kind"] == "update"


def test_api_job_stream_returns_event_stream(tmp_path: Path, monkeypatch):
    """SSE stream for an existing job returns text/event-stream content-type."""
    client = _mock_registry(monkeypatch, tmp_path)
    job_id = client.post("/api/update-db").json()["job_id"]
    resp = client.get(f"/api/jobs/{job_id}/stream")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# GET /api/report/{path} — file serving and path-traversal guard
# ---------------------------------------------------------------------------


def test_api_report_serves_existing_file(tmp_path: Path):
    client = _client(tmp_path)
    report_dir = tmp_path / "reports" / "final"
    report_dir.mkdir(parents=True)
    (report_dir / "out.md").write_text("# results", encoding="utf-8")
    resp = client.get("/api/report/out.md")
    assert resp.status_code == 200


def test_api_report_404_for_missing_file(tmp_path: Path):
    assert _client(tmp_path).get("/api/report/nonexistent.md").status_code == 404


def test_api_report_400_for_path_traversal(tmp_path: Path):
    assert _client(tmp_path).get("/api/report/../../etc/passwd").status_code in (400, 404)
