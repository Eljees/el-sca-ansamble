"""Tests for resilient_updates.pipeline_state (stage checkpoints + resume)."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates import pipeline_state as ps


def _begin(tmp_path: Path, **kw):
    kw.setdefault("target", "/data/app.tar.gz")
    kw.setdefault("tool", "all")
    return ps.begin_run(tmp_path, **kw)


# --- run key -----------------------------------------------------------------


def test_run_key_stable_and_sensitive():
    a = ps.compute_run_key("/data/app.tar.gz", "all", "fmt=auto")
    assert a == ps.compute_run_key("/data/app.tar.gz", "all", "fmt=auto")
    assert a != ps.compute_run_key("/data/other.tar.gz", "all", "fmt=auto")
    assert a != ps.compute_run_key("/data/app.tar.gz", "grype", "fmt=auto")
    assert a != ps.compute_run_key("/data/app.tar.gz", "all", "fmt=win")


# --- begin / transitions ------------------------------------------------------


def test_begin_creates_fresh_state(tmp_path: Path):
    state = _begin(tmp_path, case_id="CYBERSEC-1")
    assert state["status"] == "running"
    assert state["resumed"] is False
    assert state["case_id"] == "CYBERSEC-1"
    on_disk = json.loads(ps.state_path(tmp_path).read_text(encoding="utf-8"))
    assert on_disk["run_key"] == state["run_key"]


def test_stage_lifecycle_and_duration(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    state = ps.load_state(tmp_path)
    assert state["current_stage"] == "extract"
    assert state["stages"]["extract"]["status"] == "active"
    state = ps.stage_end(tmp_path, "extract", ok=True, rc=0)
    info = state["stages"]["extract"]
    assert info["status"] == "done"
    assert info["rc"] == 0
    assert info["duration_s"] >= 0
    assert state["current_stage"] is None


def test_stage_end_error(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "grype")
    state = ps.stage_end(tmp_path, "grype", ok=False, rc=125)
    assert state["stages"]["grype"]["status"] == "error"
    assert state["stages"]["grype"]["rc"] == 125


def test_finish_run(tmp_path: Path):
    _begin(tmp_path)
    state = ps.finish_run(tmp_path, status="done")
    assert state["status"] == "done"
    assert "finished_utc" in state


# --- resume -------------------------------------------------------------------


def test_resume_keeps_done_resets_error(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True)
    ps.stage_start(tmp_path, "sbom")
    ps.stage_end(tmp_path, "sbom", ok=False, rc=1)
    state = _begin(tmp_path, resume=True)
    assert state["resumed"] is True
    assert state["stages"]["extract"]["status"] == "done"
    assert state["stages"]["sbom"]["status"] == "pending"
    assert ps.completed_stages(state) == {"extract"}


def test_resume_with_different_target_starts_fresh(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True)
    state = ps.begin_run(tmp_path, target="/data/OTHER.tar.gz", tool="all", resume=True)
    assert state["resumed"] is False
    assert state["stages"] == {}


def test_should_skip(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True)
    assert ps.should_skip(tmp_path, "extract", target="/data/app.tar.gz")
    assert not ps.should_skip(tmp_path, "sbom", target="/data/app.tar.gz")
    # different target → never skip
    assert not ps.should_skip(tmp_path, "extract", target="/data/other.tar.gz")


def test_stage_skip_marks_resume_flag(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True)
    _begin(tmp_path, resume=True)
    state = ps.stage_skip(tmp_path, "extract")
    assert state["stages"]["extract"]["skipped_via_resume"] is True
    assert state["stages"]["extract"]["status"] == "done"


# --- summarize ----------------------------------------------------------------


def test_summarize_absent():
    assert ps.summarize(None) == {"present": False}


def test_summarize_orders_known_stages(tmp_path: Path):
    _begin(tmp_path)
    for stage in ("report", "extract", "sbom"):
        ps.stage_start(tmp_path, stage)
        ps.stage_end(tmp_path, stage, ok=True)
    out = ps.summarize(ps.load_state(tmp_path))
    assert out["present"] is True
    assert [s["stage"] for s in out["stages"]] == ["extract", "sbom", "report"]
    assert all(s["status"] == "done" for s in out["stages"])


def test_summarize_running_has_elapsed(tmp_path: Path):
    _begin(tmp_path)
    ps.stage_start(tmp_path, "cve-bin-tool")
    out = ps.summarize(ps.load_state(tmp_path))
    assert out["status"] == "running"
    assert out["current_stage"] == "cve-bin-tool"
    assert out["elapsed_s"] >= 0
    (active,) = [s for s in out["stages"] if s["stage"] == "cve-bin-tool"]
    assert active["status"] == "active"
    assert active["elapsed_s"] >= 0


def test_resume_with_wrong_schema_version_starts_fresh(tmp_path: Path):
    """A state file from a future schema version must not be reused on resume."""
    _begin(tmp_path)
    ps.stage_start(tmp_path, "extract")
    ps.stage_end(tmp_path, "extract", ok=True)
    # Tamper with schema_version to simulate a future format.
    raw = json.loads(ps.state_path(tmp_path).read_text(encoding="utf-8"))
    raw["schema_version"] = ps.SCHEMA_VERSION + 1
    ps.state_path(tmp_path).write_text(json.dumps(raw), encoding="utf-8")
    state = ps.begin_run(tmp_path, target="/data/app.tar.gz", tool="all", resume=True)
    assert state["resumed"] is False
    assert state["stages"] == {}


def test_corrupt_state_treated_as_absent(tmp_path: Path):
    ps.state_path(tmp_path).write_text("{not json", encoding="utf-8")
    assert ps.load_state(tmp_path) is None
    assert not ps.should_skip(tmp_path, "extract", target="/x")
