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


def test_list_runs_includes_saved_run_directories(tmp_path: Path):
    saved = tmp_path / "runs" / "app-20260611-120000"
    _populate(saved)
    (saved / "checkpoint.json").write_text(json.dumps({"stage": "final"}), encoding="utf-8")
    runs = list_runs(tmp_path)
    assert [r["id"] for r in runs] == ["app-20260611-120000"]
    detail = run_detail(tmp_path, "app-20260611-120000")
    assert detail is not None
    assert detail["checkpoint"]["stage"] == "final"


def test_list_runs_includes_host_report_directories(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    saved = tmp_path / "_SCA_reports" / "app-20260707-120000"
    _populate(saved)
    (saved / "checkpoint.json").write_text(json.dumps({"stage": "final"}), encoding="utf-8")
    runs = list_runs(artifacts)
    assert [r["id"] for r in runs] == ["app-20260707-120000"]
    detail = run_detail(artifacts, "app-20260707-120000")
    assert detail is not None
    assert detail["checkpoint"]["stage"] == "final"


def test_list_runs_sorted_by_date_across_name_prefixes(tmp_path: Path):
    """Newest-first by the YYYYMMDD-HHMMSS stamp, not alphabetically by name."""
    artifacts = tmp_path / "artifacts"
    for run_id in (
        "CYBERSEC-11531-20260707-132613",
        "avandoc-1.0-20260709-165134",
        "PIX_Studio-20260708-184731",
        "CYBERSEC-11531-20260707-180226",
    ):
        _populate(tmp_path / "_SCA_reports" / run_id)
    ids = [r["id"] for r in list_runs(artifacts)]
    assert ids == [
        "avandoc-1.0-20260709-165134",
        "PIX_Studio-20260708-184731",
        "CYBERSEC-11531-20260707-180226",
        "CYBERSEC-11531-20260707-132613",
    ]


def test_run_date_and_timestamp_helpers():
    from resilient_updates.dashboard import _run_date, _run_timestamp

    assert _run_timestamp("avandoc-1.0-20260709-165134") == "20260709165134"
    assert _run_date("avandoc-1.0-20260709-165134") == "2026-07-09"
    assert _run_timestamp("no-stamp-here") == ""
    assert _run_date("no-stamp-here") == ""


def test_render_index_groups_by_date_headers(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    _populate(tmp_path / "_SCA_reports" / "app-20260709-100000")
    _populate(tmp_path / "_SCA_reports" / "app-20260707-100000")
    page = render_index(artifacts)
    # one <h2> date header per distinct date, newest first
    assert page.index("2026-07-09") < page.index("2026-07-07")
    assert page.count("<h2>") == 2


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


def test_list_runs_exposes_markdown_report_path(tmp_path: Path):
    _populate(tmp_path)
    assert list_runs(tmp_path)[0]["markdown_report_path"] == "reports/final/report.md"


def test_list_runs_markdown_report_path_empty_without_md(tmp_path: Path):
    (tmp_path / "provenance").mkdir(parents=True)
    (tmp_path / "provenance" / "trivy.json").write_text(json.dumps({"tool": "trivy"}), encoding="utf-8")
    assert list_runs(tmp_path)[0]["markdown_report_path"] == ""


def test_render_index_links_report_md(tmp_path: Path):
    _populate(tmp_path)
    assert "/api/runs/current/report.md" in render_index(tmp_path)


def test_api_run_report_markdown_served_inline(tmp_path: Path):
    _populate(tmp_path)
    resp = _client(tmp_path).get("/api/runs/current/report.md")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert resp.text == "# report"


def test_api_run_report_markdown_404s(tmp_path: Path):
    """404 for an unknown run, and for a known run that has no .md."""
    (tmp_path / "provenance").mkdir(parents=True)
    (tmp_path / "provenance" / "trivy.json").write_text(json.dumps({"tool": "trivy"}), encoding="utf-8")
    client = _client(tmp_path)
    assert client.get("/api/runs/current/report.md").status_code == 404
    assert client.get("/api/runs/bogus/report.md").status_code == 404


def _uploaded_artifact(artifacts: Path, artifact_id: str = "artifact-20260709-1") -> Path:
    """Create a minimal uploaded artifact in the catalogue."""
    d = artifacts / "uploads" / artifact_id
    d.mkdir(parents=True)
    (d / "payload.bin").write_bytes(b"junk")
    (d / "artifact.json").write_text(
        json.dumps({"id": artifact_id, "original_filename": "payload.bin", "runs": []}),
        encoding="utf-8",
    )
    return d


def test_api_purge_requires_confirm(tmp_path: Path):
    _populate(tmp_path)
    d = _uploaded_artifact(tmp_path)
    client = _client(tmp_path)
    # no confirm → refused, file survives
    assert client.delete("/api/artifacts/artifact-20260709-1/purge").status_code == 400
    # wrong confirm → refused
    r = client.delete("/api/artifacts/artifact-20260709-1/purge?confirm=nope")
    assert r.status_code == 400
    assert d.is_dir()


def test_api_purge_hard_deletes_uploaded_artifact(tmp_path: Path):
    _populate(tmp_path)
    d = _uploaded_artifact(tmp_path)
    client = _client(tmp_path)
    r = client.delete("/api/artifacts/artifact-20260709-1/purge?confirm=artifact-20260709-1")
    assert r.status_code == 200
    assert r.json()["purged"] == "artifact-20260709-1"
    assert not d.exists()


def test_api_purge_refuses_legacy_artifacts(tmp_path: Path):
    """legacy-* ids mirror saved run evidence and must never be hard-deleted."""
    _populate(tmp_path)
    r = _client(tmp_path).delete("/api/artifacts/legacy-run1/purge?confirm=legacy-run1")
    assert r.status_code == 400
    assert "evidence" in r.json()["detail"]


def test_api_purge_404_for_unknown(tmp_path: Path):
    _populate(tmp_path)
    r = _client(tmp_path).delete("/api/artifacts/artifact-nope/purge?confirm=artifact-nope")
    assert r.status_code == 404


def test_catalog_purge_refuses_path_escape(tmp_path: Path):
    from resilient_updates.artifact_catalog import ArtifactCatalog

    outside = tmp_path / "outside"
    outside.mkdir()
    cat = ArtifactCatalog(tmp_path)
    with pytest.raises(ValueError):
        cat.purge_artifact("legacy-anything")
    assert outside.is_dir()


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

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
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

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
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

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
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


def test_api_artifact_upload_and_list(tmp_path: Path):
    client = _client(tmp_path)
    import io

    resp = client.post(
        "/api/artifacts/upload",
        files={"file": ("CYBERSEC-12345-app.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
    )
    assert resp.status_code == 200
    artifact = resp.json()["artifact"]
    assert artifact["case_id"] == "CYBERSEC-12345"
    listed = client.get("/api/artifacts").json()["artifacts"]
    assert listed[0]["id"] == artifact["id"]
    assert listed[0]["run_count"] == 0


def test_api_artifact_patch_and_scan(tmp_path: Path, monkeypatch):
    import io

    pytest.importorskip("fastapi")
    from resilient_updates.orchestrator import SCAN_STAGES, Job, JobRegistry

    client = _client(tmp_path)
    artifact = client.post(
        "/api/artifacts/upload",
        files={"file": ("plain.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
    ).json()["artifact"]

    patch = client.patch(
        f"/api/artifacts/{artifact['id']}",
        json={"case_id": "CYBERSEC-77777", "display_name": "patched-name"},
    )
    assert patch.status_code == 200
    assert patch.json()["artifact"]["display_name"] == "patched-name"

    captured: list[tuple[str, set[str] | None, str | None]] = []

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
        captured.append((target_host, tools, case_id))
        run_dir = tmp_path / "runs" / "patched-name-20260707-120000"
        job = Job("scan", SCAN_STAGES, target=target_host, run_dir=run_dir, case_id=case_id)
        with self._lock:
            self._jobs[job.id] = job
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    resp = client.post(
        f"/api/artifacts/{artifact['id']}/scan",
        data={"tools": "syft,trivy"},
    )
    assert resp.status_code == 200
    (target_host, tools, case_id) = captured[0]
    assert Path(target_host).name == "plain.zip"
    assert tools == {"syft", "trivy"}
    assert case_id == "CYBERSEC-77777"


def test_api_artifact_runs_and_run_file(tmp_path: Path, monkeypatch):
    import io

    pytest.importorskip("fastapi")
    from resilient_updates.orchestrator import SCAN_STAGES, Job, JobRegistry

    run_dir = tmp_path / "runs" / "artifact-run-20260707-120000"
    _populate(run_dir)
    (run_dir / "reports" / "final" / "index.html").write_text("<html>ok</html>", encoding="utf-8")

    client = _client(tmp_path)
    artifact = client.post(
        "/api/artifacts/upload",
        files={"file": ("sample.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
    ).json()["artifact"]

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
        job = Job("scan", SCAN_STAGES, target=target_host, run_dir=run_dir, case_id=case_id)
        with self._lock:
            self._jobs[job.id] = job
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    assert client.post(f"/api/artifacts/{artifact['id']}/scan").status_code == 200

    runs = client.get(f"/api/artifacts/{artifact['id']}/runs")
    assert runs.status_code == 200
    payload = runs.json()["runs"]
    assert payload[0]["id"] == "artifact-run-20260707-120000"
    assert payload[0]["default_report_path"] == "reports/final/index.html"
    file_resp = client.get("/api/runs/artifact-run-20260707-120000/files/reports/final/index.html")
    assert file_resp.status_code == 200


def test_api_delete_run_hides_saved_run(tmp_path: Path):
    saved = tmp_path / "runs" / "hide-me-20260707-120000"
    _populate(saved)
    client = _client(tmp_path)
    assert client.get("/api/runs").json()["runs"][0]["id"] == "hide-me-20260707-120000"
    resp = client.delete("/api/runs/hide-me-20260707-120000")
    assert resp.status_code == 200
    assert client.get("/api/runs").json()["runs"] == []


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


# ---------------------------------------------------------------------------
# GET /api/proxy-chain and POST /api/proxy-chain — proxy toggle
# ---------------------------------------------------------------------------


def _client_with_cfg(tmp_path: Path, default_chain: str = "corp"):
    """Create a TestClient with a minimal feed_sources.yaml that contains default_chain."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from resilient_updates.dashboard import create_app

    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "feed_sources.yaml").write_text(
        f"proxy:\n  default_chain: {default_chain}\n",
        encoding="utf-8",
    )
    return TestClient(create_app(tmp_path, repo_root=tmp_path))


def test_get_proxy_chain_returns_current_chain(tmp_path: Path):
    """GET /api/proxy-chain reads default_chain from feed_sources.yaml."""
    client = _client_with_cfg(tmp_path, default_chain="corp")
    resp = client.get("/api/proxy-chain")
    assert resp.status_code == 200
    assert resp.json() == {"chain": "corp"}


def test_get_proxy_chain_unknown_when_file_missing(tmp_path: Path):
    """When feed_sources.yaml is absent, chain is reported as 'unknown'."""
    client = _client(tmp_path)  # no configs dir
    resp = client.get("/api/proxy-chain")
    assert resp.status_code == 200
    assert resp.json()["chain"] == "unknown"


def test_post_proxy_chain_updates_yaml(tmp_path: Path):
    """POST /api/proxy-chain writes the runtime override and returns the new value."""
    client = _client_with_cfg(tmp_path, default_chain="direct")
    resp = client.post("/api/proxy-chain?chain=via-vpn")
    assert resp.status_code == 200
    assert resp.json() == {"chain": "via-vpn"}
    # Runtime override file is created…
    runtime_text = (tmp_path / "configs" / "feed_sources.runtime.yaml").read_text(encoding="utf-8")
    assert "default_chain: via-vpn" in runtime_text
    # …and the git-tracked static config stays untouched (D-NEW-2).
    cfg_text = (tmp_path / "configs" / "feed_sources.yaml").read_text(encoding="utf-8")
    assert "default_chain: direct" in cfg_text


def test_get_proxy_chain_prefers_runtime_override(tmp_path: Path):
    """GET /api/proxy-chain returns the runtime override over the static default."""
    client = _client_with_cfg(tmp_path, default_chain="corp")
    (tmp_path / "configs" / "feed_sources.runtime.yaml").write_text(
        "default_chain: via-vpn\n", encoding="utf-8"
    )
    resp = client.get("/api/proxy-chain")
    assert resp.status_code == 200
    assert resp.json() == {"chain": "via-vpn"}


def test_post_proxy_chain_roundtrip_all_values(tmp_path: Path):
    """All three valid chain values can be written and read back."""
    # Each iteration creates its own sub-directory to avoid mkdir collisions.
    for i, chain in enumerate(("direct", "corp", "via-vpn")):
        sub = tmp_path / str(i)
        sub.mkdir()
        client = _client_with_cfg(sub, default_chain="direct")
        resp = client.post(f"/api/proxy-chain?chain={chain}")
        assert resp.status_code == 200, f"chain={chain!r} failed"
        assert resp.json()["chain"] == chain


def test_post_proxy_chain_rejects_invalid_chain(tmp_path: Path):
    """Unknown chain values must return 400."""
    client = _client_with_cfg(tmp_path)
    resp = client.post("/api/proxy-chain?chain=evil")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/monitor and POST /api/scan/resume — monitor + checkpoint resume
# ---------------------------------------------------------------------------


def test_api_monitor_shape(tmp_path: Path, monkeypatch):
    """Monitor returns pipeline + containers + db_status without touching docker."""
    from resilient_updates import pipeline_state as ps

    ps.begin_run(tmp_path, target="/data/app.tar.gz", tool="all")
    ps.stage_start(tmp_path, "extract")
    monkeypatch.setattr(
        "resilient_updates.monitor.list_containers",
        lambda root: {"ok": True, "containers": []},
    )
    resp = _client(tmp_path).get("/api/monitor")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pipeline"]["present"] is True
    assert body["pipeline"]["current_stage"] == "extract"
    assert body["containers"]["ok"] is True
    assert "latest_run" in body


def test_api_scan_resume_no_checkpoint_is_409(tmp_path: Path):
    resp = _client(tmp_path).post("/api/scan/resume")
    assert resp.status_code == 409


def test_api_scan_resume_missing_target_is_409(tmp_path: Path):
    from resilient_updates import pipeline_state as ps

    ps.begin_run(tmp_path, target=str(tmp_path / "gone.tar.gz"), tool="all")
    resp = _client(tmp_path).post("/api/scan/resume")
    assert resp.status_code == 409


def test_api_scan_resume_starts_job_with_resume_flag(tmp_path: Path, monkeypatch):
    pytest.importorskip("fastapi")
    from resilient_updates import pipeline_state as ps
    from resilient_updates.orchestrator import SCAN_STAGES, Job, JobRegistry

    target = tmp_path / "app.tar.gz"
    target.write_bytes(b"data")
    ps.begin_run(tmp_path, target=str(target), tool="syft,grype")

    captured: list = []

    def fake_start_scan(self, target_host, tools=None, *, resume=False, case_id=None):
        captured.append((target_host, tools, resume, case_id))
        job = Job("scan", SCAN_STAGES, target=target_host)
        with self._lock:
            self._jobs[job.id] = job
        return job

    monkeypatch.setattr(JobRegistry, "start_scan", fake_start_scan)
    resp = _client(tmp_path).post("/api/scan/resume")
    assert resp.status_code == 200
    assert "job_id" in resp.json()
    (target_host, tools, resume, case_id) = captured[0]
    assert target_host == str(target)
    assert tools == {"syft", "grype"}
    assert resume is True
    assert case_id == ""


# ---------------------------------------------------------------------------
# Private helper coverage: _provenance_status, _deep_find, _read_env_versions
# ---------------------------------------------------------------------------


def test_provenance_status_non_dict_returns_question_mark():
    from resilient_updates.dashboard import _provenance_status

    assert _provenance_status("not-a-dict") == "?"
    assert _provenance_status(None) == "?"
    assert _provenance_status(42) == "?"


def test_deep_find_traverses_lists():
    from resilient_updates.dashboard import _deep_find

    # List containing a dict that has the key.
    assert _deep_find([{"needle": "found"}, {"other": 1}], "needle") == "found"
    # Nested: list of lists of dicts.
    assert _deep_find([[{"deep": "yes"}]], "deep") == "yes"
    # Not present returns None.
    assert _deep_find([{"a": 1}], "z") is None


def test_read_env_versions_skips_comment_and_empty_lines(tmp_path: Path):
    """Lines starting with # or without = are ignored in .env."""
    from resilient_updates.dashboard import _read_env_versions

    env = tmp_path / ".env"
    env.write_text(
        "# this is a comment\nNO_EQUALS_HERE\nGRYPE_VERSION=v1.2.3\n",
        encoding="utf-8",
    )
    versions = _read_env_versions(tmp_path)
    assert versions["GRYPE_VERSION"] == "v1.2.3"


def test_read_env_versions_falls_back_to_env_example(tmp_path: Path):
    """.env.example fills in keys not present in .env or COMPOSE_VERSION_DEFAULTS."""
    from resilient_updates.dashboard import _read_env_versions

    # .env has no version keys; use a tool name absent from COMPOSE_VERSION_DEFAULTS.
    (tmp_path / ".env").write_text("SOME_KEY=value\n", encoding="utf-8")
    # .env.example has a new tool version that the defaults dict doesn't know about.
    (tmp_path / ".env.example").write_text(
        "# example\nCUSTOM_TOOL_VERSION=v1.0.0-example\n",
        encoding="utf-8",
    )
    versions = _read_env_versions(tmp_path)
    assert versions["CUSTOM_TOOL_VERSION"] == "v1.0.0-example"


def test_read_env_versions_env_example_does_not_overwrite_env(tmp_path: Path):
    """.env value wins over .env.example."""
    from resilient_updates.dashboard import _read_env_versions

    (tmp_path / ".env").write_text("GRYPE_VERSION=v9.0.0\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("GRYPE_VERSION=v0.0.1-example\n", encoding="utf-8")
    versions = _read_env_versions(tmp_path)
    assert versions["GRYPE_VERSION"] == "v9.0.0"


# ---------------------------------------------------------------------------
# tool_status coverage: non-dict provenance entries, _fill branches
# ---------------------------------------------------------------------------


def _prov_dir(artifacts: Path) -> Path:
    d = artifacts / "provenance"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_tool_status_with_non_dict_provenance_entry(tmp_path: Path):
    """_status/_updated return None/None for non-dict provenance payloads."""
    prov = _prov_dir(tmp_path)
    # Write a valid-JSON but non-dict provenance file for grype.
    (prov / "grype.json").write_text(json.dumps("just-a-string"), encoding="utf-8")
    data = tool_status(tmp_path)
    by_name = {t["name"]: t for t in data["tools"]}
    grype = by_name["Grype"]
    assert grype["db_status"] is None
    assert grype["db_updated"] is None


def test_tool_status_cbt_source_names_are_case_insensitive(tmp_path: Path):
    """cve-bin-tool spells its curl source "Curl"; the barrel must still fill.

    Regression: dashboard looked up "CURL" verbatim in cve_range_by_source, so
    the Curl barrel showed 0% even after the source imported rows.
    """
    prov = _prov_dir(tmp_path)
    (prov / "cve-bin-tool-db.json").write_text(
        json.dumps(
            {
                "activation_status": "degraded",
                "selected_audit": {
                    "counts": {
                        "cve_range_by_source": {
                            "Curl": 206,
                            "GAD": 73324,
                            "REDHAT": 296836,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    data = tool_status(tmp_path)
    cbt = next(t for t in data["tools"] if t["name"] == "cve-bin-tool")
    by_name = {s["name"]: s for s in cbt["sources"]}
    assert by_name["CURL"]["count"] == 206
    assert by_name["CURL"]["fill"] == 100
    assert by_name["GAD"]["count"] == 73324
    assert by_name["REDHAT"]["count"] == 296836
    assert by_name["OSV"]["count"] == 0


def test_tool_status_db_updated_kind_built_vs_imported(tmp_path: Path):
    """Grype/Trivy expose the upstream BUILD date; cve-bin-tool an IMPORT time."""
    prov = _prov_dir(tmp_path)
    (prov / "grype.json").write_text(
        json.dumps({"activation_status": "active", "built": "2026-07-09T07:25:16Z"}),
        encoding="utf-8",
    )
    (prov / "trivy.json").write_text(
        json.dumps(
            {
                "activation_status": "active",
                "db_updated_at": "2026-07-09T07:49:39Z",
                "timestamp_utc": "2026-07-09T14:13:25Z",
            }
        ),
        encoding="utf-8",
    )
    (prov / "cve-bin-tool-update-status.json").write_text(
        json.dumps({"status": "degraded", "timestamp_utc": "2026-07-09T16:03:47Z"}),
        encoding="utf-8",
    )
    by_name = {t["name"]: t for t in tool_status(tmp_path)["tools"]}

    assert by_name["Grype"]["db_updated_kind"] == "built"
    # Trivy must prefer the DB's own build date over the update-run wall clock
    assert by_name["Trivy"]["db_updated"] == "2026-07-09T07:49:39Z"
    assert by_name["Trivy"]["db_updated_kind"] == "built"
    assert by_name["cve-bin-tool"]["db_updated_kind"] == "imported"
    assert by_name["Syft"]["db_updated_kind"] is None


def test_tool_status_db_updated_kind_falls_back_to_imported(tmp_path: Path):
    """Without a build date, Trivy degrades to reporting the import time."""
    prov = _prov_dir(tmp_path)
    (prov / "trivy.json").write_text(
        json.dumps({"activation_status": "active", "timestamp_utc": "2026-07-09T14:13:25Z"}),
        encoding="utf-8",
    )
    trivy = next(t for t in tool_status(tmp_path)["tools"] if t["name"] == "Trivy")
    assert trivy["db_updated"] == "2026-07-09T14:13:25Z"
    assert trivy["db_updated_kind"] == "imported"


def test_tool_status_fill_degraded(tmp_path: Path):
    """degraded status → fill == 80."""
    prov = _prov_dir(tmp_path)
    (prov / "grype.json").write_text(
        json.dumps({"activation_status": "degraded"}),
        encoding="utf-8",
    )
    data = tool_status(tmp_path)
    grype = next(t for t in data["tools"] if t["name"] == "Grype")
    assert grype["fill"] == 80


def test_tool_status_fill_lkg(tmp_path: Path):
    """last-known-good status → fill == 55."""
    prov = _prov_dir(tmp_path)
    (prov / "grype.json").write_text(
        json.dumps({"activation_status": "last-known-good"}),
        encoding="utf-8",
    )
    data = tool_status(tmp_path)
    grype = next(t for t in data["tools"] if t["name"] == "Grype")
    assert grype["fill"] == 55


def test_tool_status_fill_none_status(tmp_path: Path):
    """None/empty/missing status → fill == 0."""
    prov = _prov_dir(tmp_path)
    (prov / "grype.json").write_text(
        json.dumps({"activation_status": None}),
        encoding="utf-8",
    )
    data = tool_status(tmp_path)
    grype = next(t for t in data["tools"] if t["name"] == "Grype")
    assert grype["fill"] == 0


def test_tool_status_fill_unknown_status(tmp_path: Path):
    """Unrecognised status string → fill == 35."""
    prov = _prov_dir(tmp_path)
    (prov / "grype.json").write_text(
        json.dumps({"activation_status": "some-unknown-state"}),
        encoding="utf-8",
    )
    data = tool_status(tmp_path)
    grype = next(t for t in data["tools"] if t["name"] == "Grype")
    assert grype["fill"] == 35


# ---------------------------------------------------------------------------
# active_enabled=False → 403 on mutating endpoints
# ---------------------------------------------------------------------------


def _passive_client(tmp_path: Path, monkeypatch):
    """Create a dashboard with EL_SCA_DASHBOARD_ACTIVE=0 (read-only mode)."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from resilient_updates.dashboard import create_app

    monkeypatch.setenv("EL_SCA_DASHBOARD_ACTIVE", "0")
    return TestClient(create_app(tmp_path))


def test_api_scan_disabled_returns_403(tmp_path: Path, monkeypatch):
    import io

    client = _passive_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/scan",
        files={"file": ("a.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
    )
    assert resp.status_code == 403


def test_api_update_db_disabled_returns_403(tmp_path: Path, monkeypatch):
    client = _passive_client(tmp_path, monkeypatch)
    assert client.post("/api/update-db").status_code == 403


def test_api_route_plan_post_disabled_returns_403(tmp_path: Path, monkeypatch):
    client = _passive_client(tmp_path, monkeypatch)
    assert client.post("/api/route-plan").status_code == 403


# ---------------------------------------------------------------------------
# GET /api/route-plan — empty and populated
# ---------------------------------------------------------------------------


def test_api_route_plan_get_empty(tmp_path: Path):
    """No route-plan.json → returns empty plan."""
    client = _client(tmp_path)
    resp = client.get("/api/route-plan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["plan"] == {}
    assert body["transports"] == []
    assert body["generated_utc"] is None


def test_api_route_plan_get_populated(tmp_path: Path):
    """Existing route-plan.json → values are returned."""
    client = _client(tmp_path)
    plan_data = {
        "generated_utc": "2026-06-12T00:00:00Z",
        "plan": {"trivy": "direct"},
        "transports": ["direct"],
    }
    (tmp_path / "route-plan.json").write_text(json.dumps(plan_data), encoding="utf-8")
    resp = client.get("/api/route-plan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated_utc"] == "2026-06-12T00:00:00Z"
    assert body["plan"] == {"trivy": "direct"}
    assert "direct" in body["transports"]


def test_api_route_plan_post_runs_route_doctor(tmp_path: Path, monkeypatch):
    """POST /api/route-plan with active mode calls subprocess and returns plan."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import subprocess as _sp

    from fastapi.testclient import TestClient

    from resilient_updates.dashboard import create_app

    calls: list = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        # Simulate route-doctor writing a plan file.
        plan = {"generated_utc": "2026-06-12T10:00:00Z", "plan": {}, "transports": []}
        (tmp_path / "route-plan.json").write_text(json.dumps(plan), encoding="utf-8")
        return _sp.CompletedProcess(argv, 0)

    monkeypatch.setattr(_sp, "run", fake_run)
    client = TestClient(create_app(tmp_path))
    resp = client.post("/api/route-plan")
    assert resp.status_code == 200
    assert calls, "subprocess.run should have been called for route-doctor"
    assert resp.json()["generated_utc"] == "2026-06-12T10:00:00Z"


def test_api_route_plan_post_subprocess_error_returns_500(tmp_path: Path, monkeypatch):
    """When route-doctor raises, POST /api/route-plan returns 500."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import subprocess as _sp

    from fastapi.testclient import TestClient

    from resilient_updates.dashboard import create_app

    def boom(*args, **kwargs):
        raise OSError("docker not found")

    monkeypatch.setattr(_sp, "run", boom)
    client = TestClient(create_app(tmp_path))
    resp = client.post("/api/route-plan")
    assert resp.status_code == 500


def test_post_proxy_chain_write_error_returns_500(tmp_path: Path, monkeypatch):
    """If writing the runtime override fails, POST /api/proxy-chain returns 500."""
    from resilient_updates.dashboard import create_app

    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "feed_sources.yaml").write_text("proxy:\n  default_chain: direct\n", encoding="utf-8")

    original_write_text = Path.write_text

    def boom(self, *args, **kwargs):
        if self.name == "feed_sources.runtime.yaml":
            raise OSError("disk full")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", boom)
    client = TestClient(create_app(tmp_path, repo_root=tmp_path))
    resp = client.post("/api/proxy-chain?chain=corp")
    assert resp.status_code == 500
