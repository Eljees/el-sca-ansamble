"""Tests for resilient_updates.manifest.derive_manifest / write_manifest."""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.manifest import derive_manifest, hash_input_archive, write_manifest


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


def test_tools_extracted_from_status_json(tmp_path: Path) -> None:
    """Tools block from status.json is surfaced in the manifest."""
    (tmp_path / "status.json").write_text(
        json.dumps({"tools": {"trivy": {"version": "0.48.0"}, "grype": "0.74.3"}}),
        encoding="utf-8",
    )
    payload = derive_manifest(tmp_path)
    assert payload["tools"]["trivy"] == "0.48.0"
    assert payload["tools"]["grype"] == "0.74.3"


def test_tools_fallback_from_db_snapshot_json(tmp_path: Path) -> None:
    """When status.json has no tools, db_snapshot.json is used as fallback."""
    (tmp_path / "db_snapshot.json").write_text(
        json.dumps({"tools": {"trivy": "0.48.0", "grype": {"version": "0.74.3"}}}),
        encoding="utf-8",
    )
    payload = derive_manifest(tmp_path)
    assert payload["tools"]["trivy"] == "0.48.0"
    assert payload["tools"]["grype"] == "0.74.3"


def test_input_sha256_included_in_target_block(tmp_path: Path) -> None:
    """extraction_manifest.json input_sha256 is surfaced in the target block."""
    (tmp_path / "extraction_manifest.json").write_text(
        json.dumps({"input_sha256": "deadbeef", "status": "pass", "extracted_count": 0}),
        encoding="utf-8",
    )
    payload = derive_manifest(tmp_path, target_host="scanner-host")
    assert payload["target"]["sha256"] == "deadbeef"


def test_extraction_manifest_listed_in_artefacts(tmp_path: Path) -> None:
    """When extraction_manifest.json exists it appears under artefacts."""
    (tmp_path / "extraction_manifest.json").write_text("{}", encoding="utf-8")
    payload = derive_manifest(tmp_path)
    assert "extraction" in payload["artefacts"]


def test_glob_relpaths_ioerror_returns_empty(tmp_path: Path, monkeypatch: object) -> None:
    """OSError inside _glob_relpaths returns an empty list (provenance dir unreadable)."""

    # Patch Path.rglob on the provenance subdir to raise OSError.
    original_rglob = Path.rglob

    def _boom(self, pattern):
        if "provenance" in str(self):
            raise OSError("permission denied")
        return original_rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", _boom)

    prov_dir = tmp_path / "provenance"
    prov_dir.mkdir()
    (prov_dir / "trivy.json").write_text("{}", encoding="utf-8")

    payload = derive_manifest(tmp_path)
    # provenance should be absent or empty because OSError was swallowed
    assert "provenance" not in payload["artefacts"]


def test_hash_input_archive(tmp_path: Path) -> None:
    """hash_input_archive returns sha1 and sha256 for a file."""
    f = tmp_path / "archive.tar.gz"
    f.write_bytes(b"fake archive content")
    result = hash_input_archive(f)
    assert "sha1" in result
    assert "sha256" in result
    assert len(result["sha256"]) == 64  # hex sha256
