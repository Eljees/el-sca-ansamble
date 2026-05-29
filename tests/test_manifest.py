"""Tests for resilient_updates.manifest.derive_manifest / write_manifest."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.manifest import derive_manifest, write_manifest


def _populate(root: Path) -> None:
    """Build a realistic-ish artifacts tree for the tests."""
    (root / "sbom").mkdir(parents=True)
    (root / "sbom" / "syft.json").write_text("{}")
    (root / "sbom" / "cyclonedx.json").write_text("{}")
    (root / "reports" / "grype").mkdir(parents=True)
    (root / "reports" / "grype" / "report.json").write_text("{}")
    (root / "reports" / "final").mkdir(parents=True)
    (root / "reports" / "final" / "report.md").write_text("# x")
    (root / "provenance").mkdir()
    (root / "provenance" / "grype.json").write_text("{}")
    (root / "summary.json").write_text("{}")


def test_derive_manifest_lists_existing_artefacts(tmp_path: Path) -> None:
    _populate(tmp_path)
    payload = derive_manifest(
        tmp_path,
        case_id="CYBERSEC-1234",
        target_host="/abs/path",
        target_container="/scan-target",
    )
    a = payload["artefacts"]
    assert "sbom" in a and "sbom/syft.json" in a["sbom"]
    assert "reports" in a
    assert any("grype/report.json" in r for r in a["reports"])
    assert "provenance" in a
    assert any("grype.json" in p for p in a["provenance"])
    assert "summary" in a
    assert "final_markdown" in a


def test_derive_manifest_minimal_input_no_exception(tmp_path: Path) -> None:
    """Empty artifacts dir must not crash; produces a sparse manifest."""
    payload = derive_manifest(tmp_path)
    assert payload["schema_version"] == 1
    assert payload["case_id"] == "CYBERSEC-UNKNOWN"
    assert payload["artefacts"] == {}


def test_derive_manifest_run_id_is_deterministic(tmp_path: Path) -> None:
    """Same inputs => same run_id (modulo time-based fields)."""
    p1 = derive_manifest(tmp_path, case_id="CASE", target_host="H", target_container="C", run_id="manual-id")
    p2 = derive_manifest(tmp_path, case_id="CASE", target_host="H", target_container="C", run_id="manual-id")
    assert p1["run_id"] == p2["run_id"] == "manual-id"


def test_derive_manifest_run_id_default_is_short(tmp_path: Path) -> None:
    """When not overridden, run_id is the short_hash() helper output."""
    p = derive_manifest(tmp_path, case_id="X", target_host="H", target_container="C")
    assert len(p["run_id"]) == 12


def test_write_manifest_produces_pretty_json(tmp_path: Path) -> None:
    _populate(tmp_path)
    payload = derive_manifest(tmp_path, case_id="CASE", target_host="H")
    out = write_manifest(payload, tmp_path / "MANIFEST.json")
    raw = out.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert parsed["case_id"] == "CASE"
    assert "  " in raw  # indented
    # sort_keys=True is part of the contract for git-friendly diffs.
    keys = list(parsed.keys())
    assert keys == sorted(keys)


def test_target_block_omitted_when_no_target_info(tmp_path: Path) -> None:
    payload = derive_manifest(tmp_path)
    assert payload["target"] is None


def test_artefacts_does_not_include_missing_files(tmp_path: Path) -> None:
    # Only sbom present, nothing else.
    (tmp_path / "sbom").mkdir()
    (tmp_path / "sbom" / "syft.json").write_text("{}")
    payload = derive_manifest(tmp_path)
    assert payload["artefacts"] == {"sbom": ["sbom/syft.json"]}
