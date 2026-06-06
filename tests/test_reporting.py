from __future__ import annotations

import json
import os
import time
from pathlib import Path

from resilient_updates.reporting import build_report


def test_build_report_includes_hashes_and_db_metadata(tmp_path: Path):
    artifacts = tmp_path / "artifacts"
    (artifacts / "sbom").mkdir(parents=True)
    (artifacts / "reports" / "grype").mkdir(parents=True)
    (artifacts / "reports" / "trivy").mkdir(parents=True)
    (artifacts / "reports" / "cve-bin-tool").mkdir(parents=True)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello-report")

    (artifacts / "sbom" / "syft.json").write_text(
        json.dumps({"artifacts": [{"name": "alpha"}]}), encoding="utf-8"
    )
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")
    (artifacts / "summary.json").write_text(
        json.dumps(
            {
                "input_sha256": "feedface",
                "input_hashes": {"sha1": "abc123", "sha256": "feedface"},
                "db_snapshot_id": "snap123",
                "update_trivy_db": "unknown",
                "update_grype_db": "refreshed-this-run",
                "update_cve_db": "reused-cached",
            }
        ),
        encoding="utf-8",
    )
    (artifacts / "status.json").write_text(
        json.dumps({"tool_failures": "none", "db_drift": "fresh-or-reused"}),
        encoding="utf-8",
    )
    (artifacts / "run_manifest.json").write_text(
        json.dumps({"input_hashes": {"sha1": "abc123", "sha256": "feedface"}}),
        encoding="utf-8",
    )
    (artifacts / "db_snapshot.json").write_text(
        json.dumps(
            {
                "snapshot_id": "snap123",
                "tools": {
                    "grype": {
                        "db_version": "sha256:deadbeef",
                        "updated_at": "2026-05-16T08:00:00Z",
                        "built_at": "2026-05-16T07:00:00Z",
                        "update_state": "refreshed-this-run",
                        "db_source": "mirror-a",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, display_target=str(target), case_id="CYBERSEC-12104")
    text = output.read_text(encoding="utf-8")

    assert "SHA-1" in text
    assert "## Hash sums" in text
    assert "## Database metadata" in text
    assert "grype: state=`refreshed-this-run`" in text


def test_build_report_warns_on_stale_enrichment(tmp_path: Path, monkeypatch):
    """ADR-0004 P2: a stale EPSS cache surfaces a freshness warning."""
    artifacts = tmp_path / "artifacts"
    (artifacts / "sbom").mkdir(parents=True)
    (artifacts / "sbom" / "syft.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    for tool in ("grype", "trivy", "cve-bin-tool"):
        (artifacts / "reports" / tool).mkdir(parents=True)
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps([]), encoding="utf-8")
    (artifacts / "summary.json").write_text(json.dumps({"input_sha256": "x"}), encoding="utf-8")
    (artifacts / "status.json").write_text(
        json.dumps({"tool_failures": "none", "db_drift": "fresh"}), encoding="utf-8"
    )
    (artifacts / "run_manifest.json").write_text(json.dumps({}), encoding="utf-8")

    # Stale EPSS cache pointed at via the enrichment-root override.
    epss_dir = tmp_path / "dbroot" / "epss"
    epss_dir.mkdir(parents=True)
    epss = epss_dir / "epss_scores-current.csv"
    epss.write_text("#model_version:test\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n", encoding="utf-8")
    old = time.time() - 100 * 3600  # 100h > default 24h TTL
    os.utime(epss, (old, old))
    monkeypatch.setenv("EL_SCA_ENRICHMENT_ROOT", str(tmp_path / "dbroot"))

    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")
    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, display_target=str(target), case_id="CYBERSEC-1")
    text = output.read_text(encoding="utf-8")

    assert "exploit scores may be outdated" in text
    assert "epss: enrichment data is" in text


# ---------------------------------------------------------------------------
# Policy gate + run-history diff
# ---------------------------------------------------------------------------


def _minimal_artifacts(tmp_path: Path, *, grype_matches=None) -> tuple[Path, Path]:
    artifacts = tmp_path / "artifacts"
    for sub in ("sbom", "reports/grype", "reports/trivy", "reports/cve-bin-tool"):
        (artifacts / sub).mkdir(parents=True, exist_ok=True)
    (artifacts / "sbom" / "syft.json").write_text(
        json.dumps({"artifacts": [{"name": "alpha", "version": "1.0"}]}), encoding="utf-8"
    )
    (artifacts / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": grype_matches or []}), encoding="utf-8"
    )
    (artifacts / "reports" / "trivy" / "report.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    (artifacts / "reports" / "cve-bin-tool" / "report.json").write_text("[]", encoding="utf-8")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"policy-test")
    return artifacts, target


def _grype_match(cve: str, severity: str, pkg: str = "libfoo", version: str = "1.0"):
    return {
        "vulnerability": {"id": cve, "severity": severity},
        "artifact": {"name": pkg, "version": version, "type": "deb"},
    }


def test_policy_gate_fails_when_critical_exceeds_limit(tmp_path: Path):
    artifacts, target = _minimal_artifacts(
        tmp_path, grype_matches=[_grype_match("CVE-2026-0001", "Critical")]
    )
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "policy.json").write_text(
        json.dumps({"max_counts": {"CRITICAL": 0}}), encoding="utf-8"
    )

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-77")

    text = output.read_text(encoding="utf-8")
    assert "- Policy decision: `fail: CRITICAL=1>0`" in text


def test_policy_gate_passes_within_limits(tmp_path: Path):
    artifacts, target = _minimal_artifacts(tmp_path, grype_matches=[_grype_match("CVE-2026-0002", "High")])
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "policy.json").write_text(
        json.dumps({"max_counts": {"CRITICAL": 0}}), encoding="utf-8"
    )

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-77")

    assert "- Policy decision: `pass`" in output.read_text(encoding="utf-8")


def test_no_policy_file_keeps_no_policy_placeholder(tmp_path: Path):
    artifacts, target = _minimal_artifacts(tmp_path)

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-77")

    assert "- Policy decision: `no-policy`" in output.read_text(encoding="utf-8")


def test_diff_section_renders_against_archived_previous_run(tmp_path: Path):
    artifacts, target = _minimal_artifacts(
        tmp_path,
        grype_matches=[
            _grype_match("CVE-2026-0001", "Critical"),
            _grype_match("CVE-2026-0003", "High", pkg="libbar"),
        ],
    )
    prev = artifacts / "runs" / "CYBERSEC-77-20260101-000000"
    for sub in ("sbom", "reports/grype", "reports/trivy", "reports/cve-bin-tool"):
        (prev / sub).mkdir(parents=True)
    (prev / "sbom" / "syft.json").write_text(
        json.dumps({"artifacts": [{"name": "alpha", "version": "1.0"}]}), encoding="utf-8"
    )
    (prev / "reports" / "grype" / "report.json").write_text(
        json.dumps({"matches": [_grype_match("CVE-2026-0001", "Critical")]}), encoding="utf-8"
    )
    (prev / "reports" / "trivy" / "report.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (prev / "reports" / "cve-bin-tool" / "report.json").write_text("[]", encoding="utf-8")

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-77")

    text = output.read_text(encoding="utf-8")
    assert "## Diff с предыдущим прогоном" in text  # noqa: RUF001
    assert "CYBERSEC-77-20260101-000000" in text
    assert "`+1` новых" in text
    assert "CVE-2026-0003" in text


def test_diff_section_absent_without_history(tmp_path: Path):
    artifacts, target = _minimal_artifacts(tmp_path)

    output = tmp_path / "report.md"
    build_report(artifacts, output, target_path=target, case_id="CYBERSEC-77")

    assert "Diff с предыдущим прогоном" not in output.read_text(encoding="utf-8")  # noqa: RUF001
