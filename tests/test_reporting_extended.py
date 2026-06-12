"""Extended coverage tests for resilient_updates.reporting.

Targets the 35 lines identified as uncovered in the 88% baseline:
  target_digest edge cases, _collect_* helpers, _resolve_case_id regex,
  build_report error and fallback branches, and the cve-timeout warning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resilient_updates.reporting import (
    _collect_json_from_paths,
    _collect_paths,
    _markdown_table,
    _resolve_case_id,
    build_report,
    target_digest,
)

# ─────────────────────────────────────────────────────────────────────────────
# target_digest
# ─────────────────────────────────────────────────────────────────────────────


def test_target_digest_nonexistent_returns_none(tmp_path):
    result = target_digest(tmp_path / "no_such_file.zip")
    assert result is None  # line 29


def test_target_digest_directory_returns_hex_string(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    result = target_digest(tmp_path)
    assert isinstance(result, str) and len(result) == 64  # line 32


def test_target_digest_file_returns_hex_string(tmp_path):
    f = tmp_path / "archive.bin"
    f.write_bytes(b"\x00" * 32)
    result = target_digest(f)
    assert isinstance(result, str) and len(result) == 64


# ─────────────────────────────────────────────────────────────────────────────
# _collect_json_from_paths — fallback_names branch (lines 151-153)
# ─────────────────────────────────────────────────────────────────────────────


def test_collect_json_from_paths_fallback_used_when_relative_miss(tmp_path):
    payload = {"scanner": "trivy"}
    (tmp_path / "trivy_report.json").write_text(json.dumps(payload), encoding="utf-8")
    result = _collect_json_from_paths(
        tmp_path,
        ["reports/trivy/report.json"],  # doesn't exist
        fallback_names=["trivy_report.json"],  # exists at root level
    )
    assert result == payload  # lines 151-153


def test_collect_json_from_paths_fallback_missing_returns_none(tmp_path):
    result = _collect_json_from_paths(tmp_path, ["nope.json"], fallback_names=["also_nope.json"])
    assert result is None


def test_collect_json_from_paths_no_fallback_arg_returns_none(tmp_path):
    result = _collect_json_from_paths(tmp_path, ["nope.json"])
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# _collect_paths
# ─────────────────────────────────────────────────────────────────────────────


def test_collect_paths_nonexistent_root_returns_empty():
    result = _collect_paths(Path("/tmp/el_sca_definitely_absent_xyz_99999"))
    assert result == []  # line 167


def test_collect_paths_extracted_subdir_files_skipped(tmp_path):
    # Files under 'extracted/' are skipped unless they are extraction_manifest.json (line 174)
    extracted = tmp_path / "extracted" / "bin"
    extracted.mkdir(parents=True)
    (extracted / "payload.dat").write_bytes(b"\xff\xfe")
    manifest = tmp_path / "extracted" / "extraction_manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    normal = tmp_path / "summary.json"
    normal.write_text("{}", encoding="utf-8")

    result = _collect_paths(tmp_path)
    names = {Path(p).name for p in result}
    assert "summary.json" in names
    assert "extraction_manifest.json" in names
    assert "payload.dat" not in names  # filtered by line 174


# ─────────────────────────────────────────────────────────────────────────────
# _markdown_table — invalid epss triggers str() fallback (lines 220-221)
# ─────────────────────────────────────────────────────────────────────────────


def test_markdown_table_invalid_epss_uses_str_fallback():
    findings = [
        {
            "tool": "grype",
            "id": "CVE-2024-X",
            "severity": "CRITICAL",
            "score": "9.5",
            "vendor": "",
            "product": "ssl",
            "version": "1.0",
            "source": "grype",
            "epss": "not-a-float",  # triggers TypeError/ValueError → lines 220-221
            "kev": False,
        }
    ]
    result = _markdown_table(findings)
    assert "not-a-float" in result  # str(epss_raw) path
    assert "EPSS" in result  # enrichment columns rendered


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_case_id — regex extraction (lines 272-274)
# ─────────────────────────────────────────────────────────────────────────────


def test_resolve_case_id_extracts_from_target_path():
    # underscore is a word char, so "scan_CYBERSEC" has no \b before C.
    # Use a slash-separated path so / (non-word) precedes CYBERSEC.
    result = _resolve_case_id(None, target_path="/scans/CYBERSEC-1234.zip")
    assert result == "CYBERSEC-1234"  # lines 272-274


def test_resolve_case_id_extracts_from_display_target_first():
    result = _resolve_case_id(None, display_target="/scans/CYBERSEC-99/report", target_path="plain.zip")
    assert result == "CYBERSEC-99"


def test_resolve_case_id_falls_through_to_target_path():
    result = _resolve_case_id(None, display_target="no-match", target_path="/scans/CYBERSEC-777.tar.gz")
    assert result == "CYBERSEC-777"


def test_resolve_case_id_explicit_takes_precedence():
    result = _resolve_case_id("CYBERSEC-0001", target_path="CYBERSEC-9999.zip")
    assert result == "CYBERSEC-0001"


def test_resolve_case_id_default_when_nothing_matches():
    from resilient_updates.reporting import DEFAULT_CASE_ID

    result = _resolve_case_id(None, target_path="archive.zip")
    assert result == DEFAULT_CASE_ID


# ─────────────────────────────────────────────────────────────────────────────
# build_report — FileNotFoundError on missing artifacts (lines 290-291)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_raises_on_missing_required_artifacts(tmp_path):
    with pytest.raises(FileNotFoundError, match="missing required scan artifacts"):
        build_report(tmp_path, tmp_path / "report.md")  # lines 290-291


def test_build_report_raises_lists_missing_names(tmp_path):
    # Create only one of the four required files — others must appear in the error message
    (tmp_path / "sbom").mkdir()
    (tmp_path / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    with pytest.raises(FileNotFoundError) as exc_info:
        build_report(tmp_path, tmp_path / "report.md")
    assert "grype" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# Fixture: minimal artifacts scaffold
# ─────────────────────────────────────────────────────────────────────────────


def _scaffold(artifacts: Path) -> None:
    """Create the minimum file tree required for build_report to not raise."""
    (artifacts / "sbom").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    (artifacts / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# build_report — cve timeout flag (lines 347-352, 415)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_cve_timeout_warning_appears_in_output(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    flag = artifacts / "reports" / "cve-bin-tool" / "timeout.flag"
    flag.write_text("timed_out_after=120\n", encoding="utf-8")  # lines 347-352

    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "timed out" in content  # line 415 warning branch
    assert "120" in content


def test_build_report_cve_timeout_with_malformed_flag(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    flag = artifacts / "reports" / "cve-bin-tool" / "timeout.flag"
    flag.write_text("no_key_here\n", encoding="utf-8")

    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "timed out" in content
    assert "unknown" in content  # cve_timeout_seconds stays "unknown"


def test_build_report_cve_timeout_read_error_handled(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    flag = artifacts / "reports" / "cve-bin-tool" / "timeout.flag"
    flag.write_text("", encoding="utf-8")

    original_read_text = Path.read_text

    def boom(self, *args, **kwargs):
        if self.name == "timeout.flag":
            raise OSError("simulated read error")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", boom)
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # except on lines 351-352 — must not raise
    assert out.exists()


# ─────────────────────────────────────────────────────────────────────────────
# build_report — policy max_counts with non-integer limit (lines 379-380)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_policy_invalid_limit_continues(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    # root.parent/configs/policy.json  → tmp_path/configs/policy.json
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "policy.json").write_text(
        json.dumps({"max_counts": {"CRITICAL": "not-a-number", "HIGH": 5}}),
        encoding="utf-8",
    )
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # CRITICAL limit skipped via lines 379-380; HIGH passes
    content = out.read_text(encoding="utf-8")
    assert "pass" in content  # 0 HIGH findings ≤ 5 → pass


def test_build_report_policy_violated_shows_fail(tmp_path):
    artifacts = tmp_path / "artifacts"
    # Add a CRITICAL finding to grype report
    (artifacts / "sbom").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (artifacts / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    (artifacts / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2024-0001", "severity": "CRITICAL", "cvss": []},
                        "artifact": {"name": "openssl", "version": "3.0.0", "type": "binary"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "policy.json").write_text(json.dumps({"max_counts": {"CRITICAL": 0}}), encoding="utf-8")
    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "fail" in content


# ─────────────────────────────────────────────────────────────────────────────
# build_report — fallback text sections (lines 554, 563, 597)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_provenance_fallback_text(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    # No provenance/*.json created → line 597
    assert "Provenance JSON not found" in content


def test_build_report_db_metadata_unavailable_with_empty_tools(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    # Write a db_snapshot.json with an empty tools dict.  Because db_snapshot is
    # now truthy, run_summary.derive() will NOT override it with synthesised tool
    # entries, so db_tools stays {}.  Line 554 is hit.
    (artifacts / "db_snapshot.json").write_text(
        json.dumps({"snapshot_id": "snap-empty", "tools": {}}), encoding="utf-8"
    )
    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "Database metadata not available" in content  # line 554


def test_build_report_db_tools_non_dict_entry_skipped(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    db_snapshot = {
        "snapshot_id": "snap-001",
        "tools": {
            "trivy": "not-a-dict",  # triggers line 542 continue
            "grype": {"update_state": "ok", "db_version": "2025-01-01"},
        },
    }
    (artifacts / "db_snapshot.json").write_text(json.dumps(db_snapshot), encoding="utf-8")
    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "grype" in content
    assert "2025-01-01" in content


# ─────────────────────────────────────────────────────────────────────────────
# build_report — enrichment import exception silenced (lines 363-364)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_enrichment_exception_silenced(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)

    import resilient_updates.enrichment as _enrich

    monkeypatch.setattr(
        _enrich, "enrich_findings", lambda findings: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # must not raise; lines 363-364 handle it
    assert out.exists()


# ─────────────────────────────────────────────────────────────────────────────
# build_report — run_summary.derive exception silenced (lines 336-337)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_derive_exception_silenced(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)

    import resilient_updates.run_summary as _rs

    monkeypatch.setattr(_rs, "derive", lambda root: (_ for _ in ()).throw(RuntimeError("derive boom")))
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # lines 336-337 except handles it
    assert out.exists()


# ─────────────────────────────────────────────────────────────────────────────
# build_report — provenance files found branch (line 597)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_provenance_files_listed_in_report(tmp_path):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    prov_dir = artifacts / "provenance"
    prov_dir.mkdir()
    (prov_dir / "trivy_provenance.json").write_text(json.dumps({"tool": "trivy"}), encoding="utf-8")

    out = tmp_path / "report.md"
    build_report(artifacts, out)
    content = out.read_text(encoding="utf-8")
    assert "trivy_provenance.json" in content  # line 597 branch — provenance list rendered


# ─────────────────────────────────────────────────────────────────────────────
# build_report — source_freshness exception silenced (lines 433-434)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_source_freshness_exception_silenced(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)

    import resilient_updates.enrichment as _enrich

    monkeypatch.setattr(
        _enrich, "source_freshness", lambda: (_ for _ in ()).throw(RuntimeError("stale boom"))
    )
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # lines 433-434 except handles it
    assert out.exists()


# ─────────────────────────────────────────────────────────────────────────────
# build_report — diff_runs exception silenced (lines 490-491)
# ─────────────────────────────────────────────────────────────────────────────


def test_build_report_diff_runs_exception_silenced(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    _scaffold(artifacts)
    # Create a previous run directory matching the default case-id pattern so
    # diff_runs is actually invoked and can raise (triggering lines 490-491).
    runs_dir = artifacts / "runs"
    runs_dir.mkdir()
    prev_run = runs_dir / "CYBERSEC-UNKNOWN-20260101T000000Z"
    prev_run.mkdir()
    (prev_run / "summary.json").write_text(json.dumps({}), encoding="utf-8")

    import resilient_updates.scanner_diff as _sd

    monkeypatch.setattr(_sd, "diff_runs", lambda a, b: (_ for _ in ()).throw(RuntimeError("diff boom")))
    out = tmp_path / "report.md"
    build_report(artifacts, out)  # lines 490-491 except handles it
    assert out.exists()
