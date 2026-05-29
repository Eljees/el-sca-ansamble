"""Tests for resilient_updates.run_summary.

run_summary derives the four sidecar JSONs (summary, status, run_manifest,
db_snapshot) from existing scanner artefacts so the report header stops
showing UNKNOWN.  All tests build fixtures on a tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.run_summary import derive, write_to_disk


def _seed_root(
    root: Path,
    *,
    syft=None,
    grype=None,
    trivy=None,
    cve=None,
    extraction=None,
    prov_grype=None,
    prov_cve=None,
    prov_trivy=None,
    timeout_flag=False,
) -> Path:
    """Build a minimal artifacts/ tree."""
    (root / "sbom").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "grype").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "trivy").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "cve-bin-tool").mkdir(parents=True, exist_ok=True)
    (root / "extracted" / "current").mkdir(parents=True, exist_ok=True)
    (root / "provenance").mkdir(parents=True, exist_ok=True)

    if syft is not None:
        (root / "sbom" / "syft.json").write_text(json.dumps(syft), encoding="utf-8")
    if grype is not None:
        (root / "reports" / "grype" / "report.json").write_text(json.dumps(grype), encoding="utf-8")
    if trivy is not None:
        (root / "reports" / "trivy" / "report.json").write_text(json.dumps(trivy), encoding="utf-8")
    if cve is not None:
        (root / "reports" / "cve-bin-tool" / "report.json").write_text(json.dumps(cve), encoding="utf-8")
    if extraction is not None:
        (root / "extracted" / "current" / "extraction_manifest.json").write_text(
            json.dumps(extraction), encoding="utf-8"
        )
    if prov_grype is not None:
        (root / "provenance" / "grype.json").write_text(json.dumps(prov_grype), encoding="utf-8")
    if prov_cve is not None:
        (root / "provenance" / "cve-bin-tool-db.json").write_text(json.dumps(prov_cve), encoding="utf-8")
    if prov_trivy is not None:
        (root / "provenance" / "trivy.json").write_text(json.dumps(prov_trivy), encoding="utf-8")
    if timeout_flag:
        (root / "reports" / "cve-bin-tool" / "timeout.flag").write_text(
            "timed_out_after=1800\n", encoding="utf-8"
        )
    return root


# ---------------------------------------------------------------------------
# derive — happy path
# ---------------------------------------------------------------------------


def test_derive_counts_components_and_matches(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": [{"name": "a"}, {"name": "b"}, {"name": "c"}], "source": {}},
        grype={"matches": [{"vulnerability": {"id": "X"}}]},
        trivy={"Results": [{"Vulnerabilities": [{"VulnerabilityID": "Y"}]}]},
        cve=[{"cve_number": "CVE-2024-0001"}, {"cve_number": "CVE-2024-0002"}],
    )

    bundle = derive(root)
    s = bundle["summary"]

    assert s["coverage"]["sbom_components"] == 3
    assert s["coverage"]["grype_matches"] == 1
    assert s["coverage"]["trivy_matches"] == 1
    assert s["coverage"]["cve_bin_tool_matches"] == 2
    assert s["estimated_grype_matches"] == 1
    assert s["estimated_cve_bin_tool_matches"] == 2


def test_derive_input_sha256_single_archive(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        extraction={
            "items": [{"sha256": "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"}]
        },
    )
    s = derive(root)["summary"]
    assert s["input_sha256"] == "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"


def test_derive_input_sha256_multi_item_uses_composite_hash(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        extraction={"items": [{"sha256": "aa"}, {"sha256": "bb"}]},
    )
    s = derive(root)["summary"]
    assert s["input_sha256"].startswith("multi:")
    assert len(s["input_sha256"]) > len("multi:")


def test_derive_db_snapshot_id_combines_provenance(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        prov_grype={
            "checksum": "sha256:deadbeef",
            "freshness_metadata": {"built": "2026-05-16T07:00:00Z"},
        },
        prov_cve={
            "selected_source": "/var/lib/.../active",
            "timestamp_utc": "2026-05-16T19:38:00Z",
            "activation_status": "active",
        },
    )
    s = derive(root)["summary"]
    assert s["db_snapshot_id"]
    assert len(s["db_snapshot_id"]) == 12  # 12-char hex prefix


def test_derive_exposes_db_tool_metadata(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        prov_grype={
            "checksum": "sha256:deadbeef",
            "freshness_metadata": {"built": "2026-05-16T07:00:00Z"},
            "timestamp_utc": "2026-05-16T08:00:00Z",
            "selected_source": {"name": "mirror-a"},
            "activation_status": "active",
        },
        prov_cve={
            "selected_source": "/var/lib/.../active",
            "timestamp_utc": "2026-05-16T19:38:00Z",
            "activation_status": "active",
        },
        prov_trivy={
            "artifact_type": "trivy-db",
            "selected_source": {"name": "ghcr"},
            "timestamp_utc": "2026-05-16T06:00:00Z",
            "activation_status": "active",
        },
    )
    snapshot = derive(root)["db_snapshot"]
    assert snapshot["tools"]["grype"]["db_version"] == "sha256:deadbeef"
    assert snapshot["tools"]["grype"]["built_at"] == "2026-05-16T07:00:00Z"
    assert snapshot["tools"]["cve-bin-tool"]["updated_at"] == "2026-05-16T19:38:00Z"
    assert snapshot["tools"]["trivy"]["db_source"] == "ghcr"


# ---------------------------------------------------------------------------
# derive — failure / "UNKNOWN" cases
# ---------------------------------------------------------------------------


def test_derive_with_no_artifacts_returns_blanks_not_exceptions(tmp_path: Path):
    """All four sidecars must be returned even from an empty root."""
    root = tmp_path / "empty_artifacts"
    root.mkdir()
    bundle = derive(root)
    for key in ("summary", "status", "run_manifest", "db_snapshot"):
        assert key in bundle
    assert bundle["summary"]["coverage"]["sbom_components"] == 0
    assert bundle["summary"]["input_sha256"] == ""
    assert bundle["summary"]["db_snapshot_id"] == ""


def test_derive_flags_cve_bin_tool_timeout(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": [{"name": "a"}]},
        grype={"matches": [{"vulnerability": {"id": "X"}}]},
        cve=[],
        timeout_flag=True,
    )
    s = derive(root)["summary"]
    assert "cve-bin-tool" in s["tool_failures"]


# ---------------------------------------------------------------------------
# write_to_disk — persistence
# ---------------------------------------------------------------------------


def test_write_to_disk_creates_all_four_sidecars(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": [{"name": "a"}]},
        grype={"matches": []},
    )
    written = write_to_disk(root)
    assert set(written.keys()) == {"summary", "status", "run_manifest", "db_snapshot"}
    for path in written.values():
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["generated_by"] == "resilient_updates.run_summary"


def test_write_to_disk_respects_no_overwrite(tmp_path: Path):
    root = _seed_root(tmp_path / "artifacts", syft={"artifacts": []}, grype={"matches": []})
    sentinel = root / "summary.json"
    sentinel.write_text('{"manually_authored": true}', encoding="utf-8")

    written = write_to_disk(root, overwrite=False)

    # The manually-authored summary.json wasn't clobbered.
    assert "summary" not in written
    assert json.loads(sentinel.read_text(encoding="utf-8")) == {"manually_authored": True}
    # The other three sidecars WERE created.
    assert (root / "status.json").exists()
    assert (root / "run_manifest.json").exists()
    assert (root / "db_snapshot.json").exists()
