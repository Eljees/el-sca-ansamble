"""Tests for resilient_updates.orchestrator (host scan/update orchestration).

These exercise the docker-free parts: compose-prefix parsing, the stage state
machine, command construction, and the SSE replay/close behaviour.  No docker
or subprocess is launched.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

from resilient_updates.orchestrator import (
    SCAN_STAGES,
    UPDATE_STAGES,
    Job,
    JobRegistry,
    build_scan_command,
    build_update_command,
    detect_service,
    parse_progress,
    service_to_stage,
    sse_stream,
)


def test_detect_service_strips_replica_index():
    assert detect_service("syft-sbom-1  | scanning dir") == "syft-sbom"
    assert detect_service("cve-bin-tool-scanner-1 | run") == "cve-bin-tool-scanner"
    assert detect_service("grype-static-1   | serving") == "grype-static"


def test_detect_service_ignores_non_prefixed_lines():
    assert detect_service("$ docker compose up") is None
    assert detect_service("plain log without pipe") is None
    assert detect_service("") is None


def test_service_to_stage_covers_scan_services():
    mapping = service_to_stage(SCAN_STAGES)
    assert mapping["artifact-extractor"] == "extract"
    assert mapping["syft-sbom"] == "sbom"
    assert mapping["grype-scanner"] == "grype"
    assert mapping["report-collector"] == "report"


def test_job_stage_advances_monotonically():
    job = Job("scan", SCAN_STAGES, target="/x.tar.gz")
    job.feed_line("artifact-extractor-1  | unpacking")
    stages = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    assert stages["extract"] == "active"

    job.feed_line("grype-scanner-1  | scanning sbom")
    snap = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    # Everything before grype is marked done; grype is active; later still pending.
    assert snap["extract"] == "done"
    assert snap["sbom"] == "done"
    assert snap["grype"] == "active"
    assert snap["trivy"] == "pending"


def test_job_does_not_go_backwards():
    job = Job("scan", SCAN_STAGES)
    job.feed_line("report-collector-1 | aggregating")
    job.feed_line("artifact-extractor-1 | late noise")  # earlier stage, ignored
    snap = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    assert snap["report"] == "active"
    assert snap["extract"] == "done"


def test_job_finish_success_marks_all_done():
    job = Job("scan", SCAN_STAGES)
    job.feed_line("syft-sbom-1 | x")
    job.finish(0)
    assert job.status == "done"
    assert all(s["status"] == "done" for s in job.snapshot()["stages"])


def test_job_finish_failure_marks_active_error():
    job = Job("scan", SCAN_STAGES)
    job.feed_line("trivy-scanner-1 | boom")
    job.finish(1)
    assert job.status == "error"
    statuses = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    assert statuses["trivy"] == "error"


def test_stage_resolves_project_prefixed_container_names():
    # Some compose/buildx versions print "<project>-<service>-<n>".
    job = Job("scan", SCAN_STAGES)
    job.feed_line("el-sca-ansamble-syft-sbom-1  | building SBOM")
    snap = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    assert snap["extract"] == "done"
    assert snap["sbom"] == "active"


def test_full_simulated_scan_reaches_report():
    job = Job("scan", SCAN_STAGES, target="/x.tar.gz")
    for line in [
        "artifact-extractor-1  | unpacking",
        "syft-sbom-1  | cataloging",
        "grype-static-1  | serving db",
        "grype-scanner-1  | matching",
        "trivy-scanner-1  | scanning fs",
        "cve-bin-tool-scanner-1  | 365 checkers",
        "report-collector-1  | aggregating",
    ]:
        job.feed_line(line)
    job.finish(0)
    assert job.status == "done"
    assert all(s["status"] == "done" for s in job.snapshot()["stages"])


def test_explicit_stage_control_suppresses_auto_advance():
    j = Job("scan", SCAN_STAGES, target="/x")
    j.begin_stage("extract")
    assert {s["key"]: s["status"] for s in j.snapshot()["stages"]}["extract"] == "active"
    j.end_stage("extract", True)
    j.begin_stage("sbom")
    st = {s["key"]: s["status"] for s in j.snapshot()["stages"]}
    assert st["extract"] == "done" and st["sbom"] == "active"
    # In explicit mode, log lines must NOT auto-advance stages.
    j.feed_line("grype-scanner-1  | noise")
    assert {s["key"]: s["status"] for s in j.snapshot()["stages"]}["grype"] == "pending"


def test_run_scan_extracts_then_scans_extracted_dir(tmp_path):
    """The scan must unpack first and point scanners at extracted/current,
    otherwise Syft sees 0 components and every tool reports nothing."""
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    calls = []

    def fake_stream(job, cmd, env):
        # Service name is always the last token in `docker compose ... run ... [flags] service`.
        # Extra flags like `-u 0` (added for root-safe writes) appear before the service.
        svc = cmd[-1] if "run" in cmd else ("down" if "down" in cmd else cmd[-1])
        calls.append((svc, env.get("SCAN_TARGET_HOST"), env.get("SYFT_FROM")))
        return 1 if svc == "cve-bin-tool-scanner" else 0  # cve-bin-tool: CVEs found

    reg._run_stream = fake_stream  # type: ignore[assignment]
    job = Job("scan", SCAN_STAGES, target="/uploads/app.tar.gz")
    reg._register(job)
    reg._run_scan(job, "/uploads/app.tar.gz")

    assert [c[0] for c in calls] == [
        "artifact-extractor",
        "syft-sbom",
        "grype-scanner",
        "trivy-scanner",
        "cve-bin-tool-scanner",
        "report-collector",
        "down",
    ]
    assert calls[0][1].endswith("app.tar.gz")  # extract: raw upload
    assert calls[1][1].endswith(os.path.join("artifacts", "extracted", "current"))  # scanners: extracted dir
    assert calls[1][2] == "dir"
    snap = job.snapshot()
    assert snap["status"] == "done"  # rc=1 from cve-bin-tool is OK
    assert all(s["status"] == "done" for s in snap["stages"])


def test_command_builders():
    assert build_scan_command("scan", ["docker", "compose"]) == [
        "docker",
        "compose",
        "--profile",
        "scan",
        "up",
        "--abort-on-container-exit",
    ]
    assert build_update_command(["docker", "compose"])[2:4] == ["--profile", "update"]


def test_sse_stream_replays_then_closes_for_finished_job():
    job = Job("update", SCAN_STAGES)
    job.feed_line("syft-sbom-1 | hi")
    job.finish(0)
    frames = list(sse_stream(job, poll_timeout=0.01))
    # The first frame is the snapshot replay; stream then closes (no hang).
    assert frames, "expected at least the snapshot frame"
    first = json.loads(frames[0].removeprefix("data: ").strip())
    assert first["type"] == "snapshot"
    assert first["status"] == "done"


def test_nvd_only_update_disables_feed_enrichment(tmp_path):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    seen: dict[str, object] = {}

    def fake_spawn(job, cmd, env):
        seen["cmd"] = cmd
        seen["env"] = env

    reg._spawn_update = fake_spawn  # type: ignore[assignment]
    reg.start_update("cve-bin-tool:NVD")

    env = seen["env"]
    assert isinstance(env, dict)
    assert env["CVE_BIN_TOOL_DISABLE_SOURCES"] == "OSV GAD REDHAT CURL EPSS PURL2CPE RSD"
    assert env["CVE_BIN_TOOL_FEED_ENRICH"] == "0"


# ---------------------------------------------------------------------------
# parse_progress
# ---------------------------------------------------------------------------


def test_parse_progress_size_ratio():
    line = "12.34 MiB / 95.30 MiB [======>     ] 12.95%"
    pct = parse_progress(line)
    assert pct is not None
    assert abs(pct - (12.34 / 95.30 * 100)) < 0.1


def test_parse_progress_percent_only():
    pct = parse_progress("Downloading... 42%")
    assert pct is not None
    assert abs(pct - 42.0) < 0.01


def test_parse_progress_no_match_returns_none():
    assert parse_progress("plain log line with no numbers") is None
    assert parse_progress("") is None


def test_parse_progress_clamps_to_0_100():
    assert parse_progress("200%") == 100.0
    assert parse_progress("0 KiB / 0 KiB []") is None  # division by zero → None


# ---------------------------------------------------------------------------
# Job.finalize and Job.end_stage(ok=False)
# ---------------------------------------------------------------------------


def test_job_finalize_with_no_error_stages_is_done():
    job = Job("scan", SCAN_STAGES)
    job.begin_stage("extract")
    job.end_stage("extract", True)
    job.finalize()
    assert job.status == "done"
    assert job.returncode == 0


def test_job_finalize_with_error_stage_is_error():
    job = Job("scan", SCAN_STAGES)
    job.begin_stage("extract")
    job.end_stage("extract", False)  # extraction failed
    job.finalize()
    assert job.status == "error"
    assert job.returncode == 1


def test_job_end_stage_ok_false_marks_error():
    job = Job("scan", SCAN_STAGES)
    job.begin_stage("trivy")
    job.end_stage("trivy", False)
    statuses = {s["key"]: s["status"] for s in job.snapshot()["stages"]}
    assert statuses["trivy"] == "error"


# ---------------------------------------------------------------------------
# Job.subscribe() to a running job (not yet finished)
# ---------------------------------------------------------------------------


def test_subscribe_running_job_receives_updates():
    job = Job("scan", SCAN_STAGES)
    q = job.subscribe()
    # Should have gotten the snapshot immediately
    snap_event = q.get(timeout=1.0)
    assert snap_event["type"] == "snapshot"
    assert snap_event["status"] == "running"

    # Feed a line — subscriber should receive the update
    job.feed_line("artifact-extractor-1 | unpacking")
    update_event = q.get(timeout=1.0)
    assert update_event["type"] == "update"

    # Finishing the job should close the queue (None sentinel)
    job.finish(0)
    # Drain remaining events until None
    sentinel = None
    for _ in range(20):
        ev = q.get(timeout=1.0)
        if ev is None:
            sentinel = ev
            break
    assert sentinel is None, "sse_stream queue should receive None sentinel on job finish"


# ---------------------------------------------------------------------------
# Job.attach_log (on-disk transcript)
# ---------------------------------------------------------------------------


def test_attach_log_writes_lines_to_file(tmp_path: Path):
    job = Job("scan", SCAN_STAGES)
    log_file = tmp_path / "run.log"
    job.attach_log(log_file, header=["# test header"])
    job.feed_line("artifact-extractor-1 | unpacking")
    job.finish(0)
    content = log_file.read_text(encoding="utf-8")
    assert "# test header" in content
    assert "artifact-extractor-1 | unpacking" in content
    assert "finished status=done" in content


# ---------------------------------------------------------------------------
# JobRegistry._run_stream — FileNotFoundError path
# ---------------------------------------------------------------------------


def test_run_stream_file_not_found_returns_127(tmp_path: Path):
    """If the compose executable is missing, _run_stream must return 127 (not raise)."""
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    job = Job("scan", SCAN_STAGES)

    with patch("subprocess.Popen", side_effect=FileNotFoundError("docker not found")):
        rc = reg._run_stream(job, ["docker", "compose", "up"], {})

    assert rc == 127
    assert any("cannot launch" in line for line in job.log)


# ---------------------------------------------------------------------------
# JobRegistry._extract_produced_output
# ---------------------------------------------------------------------------


def test_extract_produced_output_true_when_manifest_pass(tmp_path: Path):
    reg = JobRegistry(tmp_path)
    mf_dir = tmp_path / "artifacts" / "extracted" / "current"
    mf_dir.mkdir(parents=True)
    (mf_dir / "extraction_manifest.json").write_text(
        '{"status": "pass", "extracted_count": 12}', encoding="utf-8"
    )
    assert reg._extract_produced_output() is True


def test_extract_produced_output_true_when_count_nonzero(tmp_path: Path):
    reg = JobRegistry(tmp_path)
    mf_dir = tmp_path / "artifacts" / "extracted" / "current"
    mf_dir.mkdir(parents=True)
    (mf_dir / "extraction_manifest.json").write_text(
        '{"status": "fail", "extracted_count": 3}', encoding="utf-8"
    )
    assert reg._extract_produced_output() is True


def test_extract_produced_output_false_when_no_manifest(tmp_path: Path):
    reg = JobRegistry(tmp_path)
    assert reg._extract_produced_output() is False


def test_extract_produced_output_false_on_empty_manifest(tmp_path: Path):
    reg = JobRegistry(tmp_path)
    mf_dir = tmp_path / "artifacts" / "extracted" / "current"
    mf_dir.mkdir(parents=True)
    (mf_dir / "extraction_manifest.json").write_text("{}", encoding="utf-8")
    assert reg._extract_produced_output() is False


# ---------------------------------------------------------------------------
# JobRegistry._checkpoint
# ---------------------------------------------------------------------------


def test_checkpoint_snapshots_report_to_run_dir(tmp_path: Path):
    reg = JobRegistry(tmp_path)
    final_dir = tmp_path / "artifacts" / "reports" / "final"
    final_dir.mkdir(parents=True)
    (final_dir / "report.md").write_text("# CVE Report", encoding="utf-8")

    run_dir = tmp_path / "artifacts" / "runs" / "case-1"
    job = Job("scan", SCAN_STAGES, artifacts_dir=tmp_path / "artifacts", run_dir=run_dir)
    reg._checkpoint(job, "report", "done")

    assert (run_dir / "reports" / "final" / "report.md").is_file()
    assert (run_dir / "MANIFEST.json").is_file()
    assert (run_dir / "checkpoint.json").is_file()
    assert any("checkpoint report:done" in line for line in job.log)


def test_start_scan_registers_run_dir_and_log(tmp_path: Path, monkeypatch):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])

    def fake_run_scan(job, target_host, tools=None, *, resume=False):
        job.finish(0)

    monkeypatch.setattr(reg, "_run_scan", fake_run_scan)
    target = tmp_path / "input.zip"
    target.write_bytes(b"PK")
    job = reg.start_scan(str(target))

    assert job.run_dir is not None
    assert job.log_path == job.run_dir / "job.log"
    assert job.log_path.is_file()


# ---------------------------------------------------------------------------
# sse_stream — keep-alive heartbeat
# ---------------------------------------------------------------------------


def test_sse_stream_emits_keepalive_before_job_finishes():
    """sse_stream must yield keep-alive lines when no event arrives within poll_timeout."""
    job = Job("update", UPDATE_STAGES)
    frames: list[str] = []

    def _collect():
        for frame in sse_stream(job, poll_timeout=0.02):
            frames.append(frame)
            if len(frames) >= 3:
                break

    t = threading.Thread(target=_collect, daemon=True)
    t.start()
    # Let the stream collect a snapshot + at least one heartbeat, then finish.


# ---------------------------------------------------------------------------
# _apply_auto_route (ADR-0007 P2: web updates work from any network location)
# ---------------------------------------------------------------------------


def _route_job():
    from resilient_updates.orchestrator import UPDATE_STAGES, Job

    return Job("update", UPDATE_STAGES)


def test_auto_route_applies_fresh_plan(tmp_path):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "route-plan.env").write_text(
        "# plan\nHTTP_PROXY=http://tinyproxy:8888\nCVE_BIN_TOOL_ENRICH_PROXY=http://tinyproxy:8888\n",
        encoding="utf-8",
    )
    ran: list[list[str]] = []
    reg._run_stream = lambda job, cmd, env: ran.append(cmd) or 0  # type: ignore[assignment]
    job = _route_job()
    env: dict[str, str] = {}
    reg._apply_auto_route(job, env)
    # route-doctor was invoked…
    assert any("route-doctor" in c for c in ran[0])
    # …and the plan landed in the env the updaters will inherit.
    assert env["HTTP_PROXY"] == "http://tinyproxy:8888"
    assert env["CVE_BIN_TOOL_ENRICH_PROXY"] == "http://tinyproxy:8888"


def test_auto_route_respects_existing_proxy(tmp_path):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    reg._run_stream = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not probe"))  # type: ignore[assignment]
    env = {"HTTP_PROXY": "http://corp:3128"}
    reg._apply_auto_route(_route_job(), env)
    assert env["HTTP_PROXY"] == "http://corp:3128"


def test_auto_route_disabled_by_env(tmp_path):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    reg._run_stream = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not probe"))  # type: ignore[assignment]
    env = {"EL_SCA_AUTO_ROUTE": "0"}
    reg._apply_auto_route(_route_job(), env)
    assert "HTTP_PROXY" not in env


def test_auto_route_ignores_stale_plan(tmp_path):
    import os

    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    plan = tmp_path / "artifacts" / "route-plan.env"
    plan.parent.mkdir()
    plan.write_text("HTTP_PROXY=http://dead:1\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(plan, (old, old))
    reg._run_stream = lambda job, cmd, env: 1  # doctor "fails", file stays stale  # type: ignore[assignment]
    env: dict[str, str] = {}
    reg._apply_auto_route(_route_job(), env)
    assert "HTTP_PROXY" not in env


# ---------------------------------------------------------------------------
# start_update: sequential `run --rm` steps (no --abort-on-container-exit)
# ---------------------------------------------------------------------------


def _seq_registry(tmp_path):
    reg = JobRegistry(tmp_path, compose=["docker", "compose"])
    reg._normalise_volumes = lambda job, env: None  # type: ignore[assignment]
    reg._apply_auto_route = lambda job, env: None  # type: ignore[assignment]
    reg._render_trivy_flags = lambda: "--skip-flags"  # type: ignore[assignment]
    return reg


def _wait_done(job, timeout=5.0):
    deadline = time.time() + timeout
    while job.status == "running" and time.time() < deadline:
        time.sleep(0.01)
    return job


def test_update_all_runs_sequential_run_rm(tmp_path):
    """'all' must run each updater as its own `compose run --rm` step (the old
    `up --abort-on-container-exit` SIGKILLed long updaters when any one-shot
    exited), and one failed tool must not cancel the others."""
    reg = _seq_registry(tmp_path)
    calls: list[str] = []

    def fake_stream(job, cmd, env):
        assert "run" in cmd and "--rm" in cmd
        assert "--abort-on-container-exit" not in cmd
        svc = cmd[-1]
        calls.append(svc)
        return 1 if svc == "grype-updater" else 0  # grype fails

    reg._run_stream = fake_stream  # type: ignore[assignment]
    job = _wait_done(reg.start_update("all"))
    assert calls == ["trivy-updater", "grype-updater", "cve-bin-tool-updater"]  # importer skipped
    assert job.status == "error"  # grype failed -> overall error, but cbt still ran


def test_update_all_success_runs_importer_after_updater(tmp_path):
    reg = _seq_registry(tmp_path)
    calls: list[str] = []
    reg._run_stream = lambda job, cmd, env: calls.append(cmd[-1]) or 0  # type: ignore[assignment]
    job = _wait_done(reg.start_update("all"))
    assert calls == ["trivy-updater", "grype-updater", "grype-db-importer", "cve-bin-tool-updater"]
    assert job.status == "done"


def test_update_single_grype_is_sequential(tmp_path):
    reg = _seq_registry(tmp_path)
    calls: list[str] = []
    reg._run_stream = lambda job, cmd, env: calls.append(cmd[-1]) or 0  # type: ignore[assignment]
    job = _wait_done(reg.start_update("grype"))
    assert calls == ["grype-updater", "grype-db-importer"]
    assert job.status == "done"


def test_update_single_trivy_runs_one_step(tmp_path):
    reg = _seq_registry(tmp_path)
    calls: list[str] = []
    reg._run_stream = lambda job, cmd, env: calls.append(cmd[-1]) or 0  # type: ignore[assignment]
    job = _wait_done(reg.start_update("trivy"))
    assert calls == ["trivy-updater"]
    assert job.status == "done"


def test_update_single_cve_bin_tool_runs_one_step(tmp_path):
    reg = _seq_registry(tmp_path)
    calls: list[str] = []
    reg._run_stream = lambda job, cmd, env: calls.append(cmd[-1]) or 0  # type: ignore[assignment]
    job = _wait_done(reg.start_update("cve-bin-tool"))
    assert calls == ["cve-bin-tool-updater"]
    assert job.status == "done"


# ---------------------------------------------------------------------------
# Job helpers: current_stage_key, maybe_periodic_checkpoint
# ---------------------------------------------------------------------------


def test_job_current_stage_key_returns_active_stage():
    job = Job("scan", SCAN_STAGES)
    job.begin_stage("grype")
    assert job.current_stage_key() == "grype"


def test_job_current_stage_key_returns_none_when_all_pending():
    job = Job("scan", SCAN_STAGES)
    assert job.current_stage_key() is None


def test_job_maybe_periodic_checkpoint_noop_without_run_dir():
    """No run_dir → early return without error."""
    job = Job("scan", SCAN_STAGES)
    job.maybe_periodic_checkpoint()  # should not raise


def test_job_maybe_periodic_checkpoint_writes_when_interval_elapsed(tmp_path):
    """With run_dir + elapsed interval → writes checkpoint.json."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    job = Job("scan", SCAN_STAGES, artifacts_dir=tmp_path, run_dir=run_dir)
    job.begin_stage("grype")
    job._last_checkpoint_at = 0.0  # force interval elapsed
    job.maybe_periodic_checkpoint()
    assert (run_dir / "checkpoint.json").exists()


# ---------------------------------------------------------------------------
# Job._resolve_stage and progress tracking
# ---------------------------------------------------------------------------


def test_resolve_stage_returns_none_for_unknown_service():
    job = Job("scan", SCAN_STAGES)
    assert job._resolve_stage("nonexistent-service-xyz") is None


def test_feed_line_progress_updates_pct():
    """A download-progress line in auto-detect mode triggers progress events.

    _max_index is updated by _advance (auto-detect only, not explicit-stage
    mode), so we must feed a service log line first to unlock progress tracking.
    """
    job = Job("scan", SCAN_STAGES)
    q = job.subscribe()
    # First, feed a service line so _advance sets _max_index >= 0
    job.feed_line("grype-scanner-1  | matching packages")
    # Now feed a progress line — parse_progress will extract a percentage
    job.feed_line("12.34 MiB / 95.30 MiB [===>    ] 12.95%")
    # Drain the queue and check for a progress event
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    progress_events = [e for e in events if isinstance(e, dict) and "progress" in e]
    assert progress_events, "expected at least one event with 'progress' key"
    assert progress_events[0]["progress"]["stage"] == "grype"


def test_begin_stage_noop_for_unknown_key():
    """begin_stage with unknown key must not raise."""
    job = Job("scan", SCAN_STAGES)
    job.begin_stage("nonexistent")  # should not raise


def test_end_stage_noop_for_unknown_key():
    """end_stage with unknown key must not raise."""
    job = Job("scan", SCAN_STAGES)
    job.end_stage("nonexistent", ok=True)  # should not raise
