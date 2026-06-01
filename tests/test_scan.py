"""Tests for resilient_updates.scan — pipeline plan builder (ADR-0005 P1)."""

from __future__ import annotations

from resilient_updates.scan import build_plan, format_plan


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
