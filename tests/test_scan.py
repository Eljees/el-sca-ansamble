"""Tests for resilient_updates.scan — pipeline plan builder (ADR-0005 P1) and
the subprocess orchestrator (P2, exercised with a fake runner)."""

from __future__ import annotations

from types import SimpleNamespace

from resilient_updates.scan import build_plan, format_plan, run_scan


def _make_runner(*, codes=None, outs=None, recorder=None):
    """Fake ``subprocess.run``: returncode/stdout chosen by substring of the cmd."""
    codes = codes or {}
    outs = outs or {}

    def runner(cmd, *, timeout=None, capture_output=True, text=True, env=None):
        if recorder is not None:
            recorder.append({"cmd": cmd, "timeout": timeout, "env": env})
        joined = " ".join(cmd)
        rc = 0
        for sub, c in codes.items():
            if sub in joined:
                rc = c
        out = ""
        for sub, o in outs.items():
            if sub in joined:
                out = o
        return SimpleNamespace(returncode=rc, stdout=out, stderr="")

    return runner


def _names(plan):
    return [s["step"] for s in plan]


def test_all_tools_order():
    plan = build_plan(target="x")
    assert _names(plan) == [
        "preflight",
        "syft-sbom",
        "grype-db-status",
        "grype-scan",
        "trivy-db-status",
        "trivy-render-flags",
        "trivy-scan",
        "cve-bin-tool-db-status",
        "cve-bin-tool-scan",
        "collect-report",
        "write-run-summary",
        "scanner-diff",
        "manifest",
    ]


def test_single_tool_grype_excludes_others():
    names = _names(build_plan(target="x", tool="grype"))
    assert "grype-scan" in names
    assert "trivy-scan" not in names
    assert "cve-bin-tool-scan" not in names
    assert "syft-sbom" not in names


def test_extract_inserts_step_after_preflight():
    names = _names(build_plan(target="x", extract=True))
    assert names[1] == "extract"


def test_update_db_adds_updaters():
    names = _names(build_plan(target="x", tool="grype", update_db=True))
    assert "grype-update" in names
    assert "grype-db-import" in names


def test_cve_timeout_and_sbom_recorded():
    plan = build_plan(target="x", tool="cve-bin-tool", timeout=900, sbom_scan=True)
    scan = next(s for s in plan if s["step"] == "cve-bin-tool-scan")
    assert scan["timeout"] == 900
    assert scan["sbom_scan"] is True


def test_profile_threaded_into_scanner_cmd():
    plan = build_plan(target="x", tool="trivy", profile="win")
    scan = next(s for s in plan if s["step"] == "trivy-scan")
    assert "--profile" in scan["cmd"]
    assert "win" in scan["cmd"]


def test_format_plan_human_readable():
    out = format_plan(build_plan(target="/tmp/a.tar"), target="/tmp/a.tar")
    assert "cli scan plan" in out
    assert "preflight" in out
    assert "manifest" in out


# ---------------------------------------------------------------------------
# run_scan (P2) — driven by a fake subprocess runner
# ---------------------------------------------------------------------------


def test_run_scan_all_ok():
    result = run_scan(target="x", runner=_make_runner(), env={})
    assert result["status"] == "ok"
    assert len(result["steps"]) == len(build_plan(target="x"))
    assert all(s["ok"] for s in result["steps"])


def test_run_scan_stops_on_first_failure():
    runner = _make_runner(codes={"grype-scanner": 1})
    result = run_scan(target="x", runner=runner, env={})
    assert result["status"] == "failed"
    # stopped at grype-scan; trivy/cve-bin-tool never ran
    names = [s["step"] for s in result["steps"]]
    assert names[-1] == "grype-scan"
    assert "trivy-scan" not in names


def test_run_scan_cve_bin_tool_exit1_is_success():
    runner = _make_runner(codes={"cve-bin-tool-scanner": 1})
    result = run_scan(target="x", tool="cve-bin-tool", runner=runner, env={})
    assert result["status"] == "ok"
    scan = next(s for s in result["steps"] if s["step"] == "cve-bin-tool-scan")
    assert scan["returncode"] == 1 and scan["ok"] is True


def test_run_scan_threads_render_flags_into_trivy_env():
    recorder: list = []
    runner = _make_runner(outs={"render-flags trivy": "--db-repository ghcr.io/x"}, recorder=recorder)
    run_scan(target="x", tool="trivy", runner=runner, env={})
    trivy_scan_call = next(c for c in recorder if "trivy-scanner" in " ".join(c["cmd"]))
    assert trivy_scan_call["env"].get("TRIVY_RENDERED_FLAGS") == "--db-repository ghcr.io/x"


def test_run_scan_passes_timeout_to_cve_bin_tool():
    recorder: list = []
    runner = _make_runner(recorder=recorder)
    run_scan(target="x", tool="cve-bin-tool", timeout=900, runner=runner, env={})
    cve_call = next(c for c in recorder if "cve-bin-tool-scanner" in " ".join(c["cmd"]))
    assert cve_call["timeout"] == 900
