"""Tests for resilient_updates.monitor (container/pipeline status view)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from resilient_updates import monitor, pipeline_state as ps


class _Proc:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = ""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


# --- list_containers ----------------------------------------------------------


def test_list_containers_ndjson(tmp_path: Path):
    lines = "\n".join(
        json.dumps(o)
        for o in (
            {
                "Name": "el-sca-dashboard-1",
                "Service": "dashboard",
                "State": "running",
                "Status": "Up 2 hours",
            },
            {"Name": "el-sca-grype-1", "Service": "grype-scanner", "State": "exited", "Status": "Exited (0)"},
        )
    )
    with patch("resilient_updates.monitor.subprocess.run", return_value=_Proc(stdout=lines)):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is True
    assert [c["service"] for c in out["containers"]] == ["dashboard", "grype-scanner"]
    assert out["containers"][0]["state"] == "running"


def test_list_containers_json_array(tmp_path: Path):
    payload = json.dumps([{"Name": "x", "Service": "syft-sbom", "State": "exited", "Status": "Exited (0)"}])
    with patch("resilient_updates.monitor.subprocess.run", return_value=_Proc(stdout=payload)):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is True
    assert out["containers"][0]["service"] == "syft-sbom"


def test_list_containers_docker_missing(tmp_path: Path):
    with patch("resilient_updates.monitor.subprocess.run", side_effect=FileNotFoundError):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is False
    assert "docker" in out["error"]


def test_list_containers_nonzero_rc(tmp_path: Path):
    with patch(
        "resilient_updates.monitor.subprocess.run",
        return_value=_Proc(returncode=1, stderr="no compose file"),
    ):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is False
    assert "no compose file" in out["error"]


# --- db status / log tail -----------------------------------------------------


def test_summarize_db_status(tmp_path: Path):
    db = tmp_path / "db_status"
    db.mkdir()
    (db / "grype.json").write_text(
        json.dumps({"tool": "grype", "exists": True, "age_hours": 5.2, "status": "fresh"}),
        encoding="utf-8",
    )
    (db / "broken.json").write_text("{nope", encoding="utf-8")
    out = monitor.summarize_db_status(tmp_path)
    assert out == [{"tool": "grype", "exists": True, "age_hours": 5.2, "status": "fresh"}]


def test_tail_log(tmp_path: Path):
    (tmp_path / "run-scan.log").write_text("\n".join(f"line{i}" for i in range(40)), encoding="utf-8")
    tail = monitor.tail_log(tmp_path, lines=5)
    assert tail == ["line35", "line36", "line37", "line38", "line39"]
    assert monitor.tail_log(tmp_path / "nope") == []


def test_latest_run_snapshot_reads_newest_checkpoint(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    old = artifacts / "runs" / "old-20260706-100000"
    new = artifacts / "runs" / "new-20260706-110000"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "checkpoint.json").write_text(
        json.dumps({"stage": "extract", "status": "running", "updated_at_utc": "2026-07-06T10:00:00Z"}),
        encoding="utf-8",
    )
    (new / "checkpoint.json").write_text(
        json.dumps({"stage": "report", "status": "done", "updated_at_utc": "2026-07-06T11:00:00Z"}),
        encoding="utf-8",
    )
    (new / "MANIFEST.json").write_text("{}", encoding="utf-8")

    out = monitor.latest_run_snapshot(artifacts)

    assert out is not None
    assert out["id"] == new.name
    assert out["checkpoint"]["stage"] == "report"
    assert out["manifest_present"] is True


def test_latest_run_snapshot_reads_host_reports_dir(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    saved = tmp_path / "_SCA_reports" / "app-20260707-120000"
    saved.mkdir(parents=True)
    (saved / "checkpoint.json").write_text(
        json.dumps({"stage": "report", "status": "done", "updated_at_utc": "2026-07-07T12:00:00Z"}),
        encoding="utf-8",
    )

    out = monitor.latest_run_snapshot(artifacts)

    assert out is not None
    assert out["id"] == saved.name
    assert out["checkpoint"]["stage"] == "report"


# --- gather_status + render_text -----------------------------------------------


def test_gather_status_and_render(tmp_path: Path):
    ps.begin_run(tmp_path, target="/data/app.tar.gz", tool="all", case_id="CYBERSEC-7")
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True, rc=0)
    ps.stage_start(tmp_path, "sbom")
    with patch(
        "resilient_updates.monitor.subprocess.run",
        return_value=_Proc(
            stdout=json.dumps({"Name": "x", "Service": "syft-sbom", "State": "running", "Status": "Up"})
        ),
    ):
        status = monitor.gather_status(tmp_path, repo_root=tmp_path)
    assert status["pipeline"]["present"] is True
    assert status["pipeline"]["current_stage"] == "sbom"
    assert status["containers"]["ok"] is True
    assert "latest_run" in status

    text = monitor.render_text(status)
    assert "Пайплайн" in text
    assert "extract" in text
    assert "syft-sbom" in text


def test_render_text_no_state_no_docker():
    text = monitor.render_text(
        {
            "pipeline": {"present": False},
            "containers": {"ok": False, "error": "docker not found on PATH"},
            "db_status": [],
            "log_tail": [],
        }
    )
    assert "pipeline_state.json" in text
    assert "docker недоступен" in text


# --- additional branch coverage -----------------------------------------------


def test_list_containers_timeout(tmp_path: Path):
    """TimeoutExpired → ok=False with timed-out message (lines 41-42)."""
    with patch(
        "resilient_updates.monitor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["docker"], timeout=30),
    ):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is False
    assert "timed out" in out["error"]


def test_list_containers_json_array_invalid(tmp_path: Path):
    """JSON array that fails to parse → containers=[] but ok=True (lines 55-56)."""
    with patch("resilient_updates.monitor.subprocess.run", return_value=_Proc(stdout="[not-valid-json")):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is True
    assert out["containers"] == []


def test_list_containers_ndjson_empty_and_garbage_lines(tmp_path: Path):
    """Empty lines and non-JSON lines in NDJSON are skipped (lines 61, 64-65)."""
    # Empty line must be in the MIDDLE so proc.stdout.strip() doesn't remove it.
    ndjson = "\n".join(
        [
            json.dumps(
                {"Name": "el-sca-grype-1", "Service": "grype-scanner", "State": "running", "Status": "Up"}
            ),
            "",  # empty line in the middle → if not line: continue (line 61)
            "not-json-at-all",  # ValueError → continue (lines 64-65)
        ]
    )
    with patch("resilient_updates.monitor.subprocess.run", return_value=_Proc(stdout=ndjson)):
        out = monitor.list_containers(tmp_path)
    assert out["ok"] is True
    assert len(out["containers"]) == 1
    assert out["containers"][0]["service"] == "grype-scanner"


def test_summarize_db_status_non_dict_json(tmp_path: Path):
    """A JSON file whose value is not a dict is silently skipped (line 93)."""
    db = tmp_path / "db_status"
    db.mkdir()
    (db / "weird.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")  # list, not dict
    (db / "ok.json").write_text(
        json.dumps({"tool": "grype", "exists": True, "age_hours": 1.0, "status": "fresh"}),
        encoding="utf-8",
    )
    out = monitor.summarize_db_status(tmp_path)
    assert len(out) == 1
    assert out[0]["tool"] == "grype"


def test_render_text_resumed_and_skipped():
    """render_text covers resumed flag (line 151) and skipped_via_resume (line 163)."""
    status = {
        "pipeline": {
            "present": True,
            "status": "running",
            "current_stage": "grype",
            "elapsed_s": 120.0,
            "resumed": True,
            "target": "/data/app.tar.gz",
            "stages": [
                {"stage": "extract", "status": "done", "duration_s": 5.0, "skipped_via_resume": True},
                {"stage": "sbom", "status": "done", "duration_s": 10.0, "skipped_via_resume": False},
                {"stage": "grype", "status": "active", "elapsed_s": 60.0, "skipped_via_resume": False},
            ],
        },
        "containers": {"ok": True, "containers": []},
        "db_status": [],
        "log_tail": [],
    }
    text = monitor.render_text(status)
    assert "продолжен с чекпоинта" in text  # noqa: RUF001
    assert "skip:checkpoint" in text
    assert "120s" in text
    assert "extract" in text


def test_render_text_db_status_and_log_tail():
    """render_text covers db_status section (lines 180-183) and log_tail (lines 187-188)."""
    status = {
        "pipeline": {"present": False},
        "containers": {"ok": True, "containers": []},
        "db_status": [
            {"tool": "trivy", "age_hours": 2.5, "status": "fresh"},
            {"tool": "grype", "age_hours": None, "status": "unknown"},
        ],
        "log_tail": ["2026-06-13 10:00 extracting...", "2026-06-13 10:01 done"],
    }
    text = monitor.render_text(status)
    assert "Базы" in text
    assert "trivy" in text
    assert "2.5h" in text
    assert "?" in text  # grype age_hours=None → "?"
    assert "Лог" in text
    assert "extracting" in text
