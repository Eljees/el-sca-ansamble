"""Tests for per-run artifact snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.run_layout import (
    _copy_file,
    _copy_tree,
    archive_current_run,
    project_name_from_target,
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


# ─────────────────────────────────────────────────────────────────────────────
# project_name_from_target — no target_host (line 69)
# ─────────────────────────────────────────────────────────────────────────────


def test_project_name_from_target_none_returns_scan() -> None:
    assert project_name_from_target(None) == "scan"  # line 69


# ─────────────────────────────────────────────────────────────────────────────
# resolve_run_dir — invalid mode clamped to artifacts (line 99),
# near-source with nonexistent target (lines 105-106)
# ─────────────────────────────────────────────────────────────────────────────


def test_resolve_run_dir_invalid_mode_falls_back_to_artifacts(tmp_path: Path) -> None:
    run_dir = resolve_run_dir(
        artifacts_dir=tmp_path / "artifacts",
        target_host=None,
        mode="INVALID-MODE",  # line 99 clamped
        timestamp=0,
    )
    assert run_dir.parent.name == "runs"
    assert run_dir.parent.parent == tmp_path / "artifacts"


def test_resolve_run_dir_near_source_nonexistent_target_returns_parent(tmp_path: Path) -> None:
    run_dir = resolve_run_dir(
        artifacts_dir=tmp_path / "artifacts",
        target_host=str(tmp_path / "not_there" / "app.zip"),
        mode="near-source",  # lines 105-106: target absent → still returns parent
        timestamp=0,
    )
    assert run_dir.parent == tmp_path / "not_there"


# ─────────────────────────────────────────────────────────────────────────────
# _copy_file — noop when src doesn't exist (line 113)
# _copy_tree — noop when src doesn't exist (line 120), rmtree when dst exists (line 122)
# ─────────────────────────────────────────────────────────────────────────────


def test_copy_file_noop_for_nonexistent_src(tmp_path: Path) -> None:
    dst = tmp_path / "dst.txt"
    _copy_file(tmp_path / "no_file.txt", dst)  # line 113: returns early
    assert not dst.exists()


def test_copy_tree_noop_for_nonexistent_src(tmp_path: Path) -> None:
    dst = tmp_path / "dst_dir"
    _copy_tree(tmp_path / "no_dir", dst)  # line 120: returns early
    assert not dst.exists()


def test_copy_tree_removes_existing_dst(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    dst.mkdir()
    (dst / "old.txt").write_text("stale", encoding="utf-8")
    _copy_tree(src, dst)  # line 122: dst exists → rmtree then copytree
    assert (dst / "a.txt").exists()
    assert not (dst / "old.txt").exists()


# ─────────────────────────────────────────────────────────────────────────────
# snapshot_artifacts — include_extracted_tree=True (lines 170-171)
# ─────────────────────────────────────────────────────────────────────────────


def test_snapshot_artifacts_include_extracted_tree(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    run_dir = tmp_path / "runs" / "case-full"
    _seed_artifacts(artifacts)
    (artifacts / "extracted" / "current" / "payload.bin").write_bytes(b"\x00" * 8)

    snapshot_artifacts(
        artifacts,
        run_dir,
        include_extracted_tree=True,  # lines 170-171
    )
    assert (run_dir / "extracted" / "current" / "payload.bin").exists()
