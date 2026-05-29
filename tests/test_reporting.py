from __future__ import annotations

import json
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
