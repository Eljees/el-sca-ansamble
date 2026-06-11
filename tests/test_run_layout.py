"""Tests for per-run artifact snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.run_layout import (
    archive_current_run,
    resolve_run_dir,
    slugify,
    snapshot_artifacts,
)


def _seed_artifacts(root: Path) -> None:
    (root / "sbom").mkdir(parents=True)
    (root / "sbom" / "syft.json").write_text('{"artifacts":[]}', encoding="utf-8")
    (root / "reports" / "final").mkdir(parents=True)
    (root / "reports" / "final" / "index.html").write_text("<html></html>", encoding="utf-8")
    (root / "reports" / "grype").mkdir(parents=True)
    (root / "reports" / "grype" / "report.json").write_text('{"matches":[]}', encoding="utf-8")
    (root / "provenance").mkdir(parents=True)
    (root / "provenance" / "grype.json").write_text('{"activation_status":"active"}', encoding="utf-8")
    (root / "extracted" / "current").mkdir(parents=True)
    (root / "extracted" / "current" / "extraction_manifest.json").write_text(
        '{"status":"pass","extracted_count":1}', encoding="utf-8"
    )
    (root / "summary.json").write_text("{}", encoding="utf-8")


def test_slugify_keeps_useful_name() -> None:
    assert slugify("Grafana Enterprise 12.3.0") == "Grafana-Enterprise-12.3.0"
    assert slugify("   ") == "scan"


def test_resolve_run_dir_near_source(tmp_path: Path) -> None:
    target = tmp_path / "input" / "app.tar.gz"
    target.parent.mkdir()
    target.write_text("x", encoding="utf-8")
    run_dir = resolve_run_dir(
        artifacts_dir=tmp_path / "artifacts",
        target_host=str(target),
        case_id=None,
        mode="near-source",
        timestamp=0,
    )
    assert run_dir.parent == target.parent
    assert run_dir.name.startswith("app.tar-19700101-")


def test_snapshot_artifacts_writes_manifest_and_checkpoint(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    run_dir = tmp_path / "runs" / "case-1"
    _seed_artifacts(artifacts)
    result = snapshot_artifacts(
        artifacts,
        run_dir,
        case_id="CYBERSEC-1",
        target_host="/source/app.tar.gz",
        stage="report",
        status="done",
    )
    assert Path(result["run_dir"]).is_dir()
    assert (run_dir / "sbom" / "syft.json").is_file()
    assert (run_dir / "reports" / "final" / "index.html").is_file()
    assert (run_dir / "extracted" / "current" / "extraction_manifest.json").is_file()
    assert not (run_dir / "extracted" / "current" / "payload.bin").exists()
    manifest = json.loads((run_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    checkpoint = json.loads((run_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert manifest["case_id"] == "CYBERSEC-1"
    assert checkpoint["stage"] == "report"
    assert checkpoint["status"] == "done"


def test_archive_current_run_artifacts_mode(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    _seed_artifacts(artifacts)
    result = archive_current_run(
        artifacts_dir=artifacts,
        target_host=str(tmp_path / "input.zip"),
        case_id="CASE-1",
        mode="artifacts",
    )
    run_dir = Path(result["run_dir"])
    assert run_dir.parent == artifacts / "runs"
    assert (run_dir / "MANIFEST.json").is_file()
