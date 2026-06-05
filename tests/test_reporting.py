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
