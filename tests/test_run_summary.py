"""Tests for resilient_updates.run_summary.

run_summary derives the four sidecar JSONs (summary, status, run_manifest,
db_snapshot) from existing scanner artefacts so the report header stops
showing UNKNOWN.  All tests build fixtures on a tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.run_summary import (
    _count_list,
    _cve_provenance_state,
    _db_drift,
    _grype_provenance_state,
    _input_hashes,
    _input_sha256,
    _top_level_input_items,
    derive,
    write_to_disk,
)


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


def test_derive_input_sha256_prefers_single_top_level_archive(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        extraction={
            "items": [
                {"archive": "/input/root.zip", "sha256": "rootsha", "depth": 0},
                {"archive": "/tmp/nested.docx", "sha256": "nestedsha1", "depth": 1},
                {"archive": "/tmp/nested.gz", "sha256": "nestedsha2", "depth": 1},
            ]
        },
    )
    s = derive(root)["summary"]
    assert s["input_sha256"] == "rootsha"


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


def test_derive_zero_findings_are_not_tool_failures(tmp_path: Path):
    root = _seed_root(
        tmp_path / "artifacts",
        syft={"artifacts": []},
        grype={"matches": []},
        trivy={"Results": []},
        cve=[],
    )
    s = derive(root)["summary"]
    assert s["tool_failures"] == "none"


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


# ---------------------------------------------------------------------------
# db-status probe fallback (scan-only runs without provenance)
# ---------------------------------------------------------------------------


def _seed_probe(root: Path, tool: str, *, exists=True, age=9.5, ts="2026-06-05T06:50:00+00:00"):
    (root / "db_status").mkdir(parents=True, exist_ok=True)
    (root / "db_status" / f"{tool}.json").write_text(
        json.dumps(
            {
                "tool": tool,
                "exists": exists,
                "age_hours": age,
                "warning": bool(age and age > 24),
                "timestamp_utc": ts,
            }
        ),
        encoding="utf-8",
    )


def test_db_probe_fills_unknown_states_when_no_provenance(tmp_path: Path):
    root = _seed_root(tmp_path)
    for tool in ("grype", "trivy", "cve-bin-tool"):
        _seed_probe(root, tool, age=12.3)

    snapshot = derive(root)["db_snapshot"]

    for tool in ("grype", "trivy", "cve-bin-tool"):
        assert snapshot["tools"][tool]["update_state"] == "cached-present"
        assert snapshot["tools"][tool]["db_version"] == "cached (age 12.3h)"
        assert snapshot["tools"][tool]["updated_at"]
    assert snapshot["snapshot_id"]


def test_db_probe_missing_db_reports_missing(tmp_path: Path):
    root = _seed_root(tmp_path)
    _seed_probe(root, "grype", exists=False, age=None)

    snapshot = derive(root)["db_snapshot"]

    assert snapshot["tools"]["grype"]["update_state"] == "missing"
    assert snapshot["tools"]["grype"]["db_version"] == ""


def test_provenance_always_wins_over_probe(tmp_path: Path):
    root = _seed_root(
        tmp_path,
        prov_grype={
            "activation_status": "active",
            "checksum": "deadbeef",
            "freshness_metadata": {"built": "2026-06-01T00:00:00Z"},
            "timestamp_utc": "2026-06-01T00:00:01Z",
        },
    )
    _seed_probe(root, "grype", age=99.0)

    snapshot = derive(root)["db_snapshot"]

    assert snapshot["tools"]["grype"]["update_state"] == "refreshed-this-run"
    assert snapshot["tools"]["grype"]["db_version"] == "deadbeef"


def test_no_probe_files_keeps_unknown(tmp_path: Path):
    root = _seed_root(tmp_path)

    snapshot = derive(root)["db_snapshot"]

    assert snapshot["tools"]["grype"]["update_state"] == "unknown"
    assert snapshot["snapshot_id"] == ""


# ---------------------------------------------------------------------------
# _count_list helper
# ---------------------------------------------------------------------------


def test_count_list_non_list_returns_zero():
    """Non-list input returns 0."""
    assert _count_list(None) == 0
    assert _count_list({}) == 0
    assert _count_list("string") == 0


# ---------------------------------------------------------------------------
# _input_sha256 edge cases
# ---------------------------------------------------------------------------


def test_input_sha256_empty_items_returns_none():
    """Empty items list → None."""
    assert _input_sha256({"items": []}) is None


def test_input_sha256_multi_item_no_valid_sha256():
    """Multiple items with no valid sha256 values → None."""
    result = _input_sha256({"items": [{}, {}]})
    assert result is None


def test_input_sha256_single_item_empty_sha():
    """Single item with empty sha256 → None."""
    assert _input_sha256({"items": [{"sha256": ""}]}) is None


def test_top_level_input_items_prefers_depth_zero():
    items = _top_level_input_items(
        {
            "items": [
                {"archive": "root.zip", "sha256": "root", "depth": 0},
                {"archive": "nested.zip", "sha256": "nested", "depth": 1},
            ]
        }
    )
    assert items == [{"archive": "root.zip", "sha256": "root", "depth": 0}]


# ---------------------------------------------------------------------------
# _input_hashes — file path hashing
# ---------------------------------------------------------------------------


def test_input_hashes_with_real_file(tmp_path: Path):
    """_input_hashes returns sha1+sha256 when the archive file exists."""
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"fake archive")
    extraction = {"items": [{"archive": str(archive), "sha256": "abc"}]}
    result = _input_hashes(extraction)
    assert "sha1" in result
    assert "sha256" in result


def test_input_hashes_missing_file_returns_empty(tmp_path: Path):
    """Non-existent archive path → empty dict."""
    extraction = {"items": [{"archive": str(tmp_path / "no.tar.gz")}]}
    assert _input_hashes(extraction) == {}


def test_input_hashes_prefers_single_top_level_file(tmp_path: Path):
    """Nested archives do not prevent hashing the original input file."""
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"root archive")
    extraction = {
        "items": [
            {"archive": str(archive), "sha256": "root", "depth": 0},
            {"archive": str(tmp_path / "nested.docx"), "sha256": "nested", "depth": 1},
        ]
    }
    result = _input_hashes(extraction)
    assert "sha1" in result
    assert "sha256" in result


# ---------------------------------------------------------------------------
# _grype_provenance_state branches
# ---------------------------------------------------------------------------


def test_grype_provenance_state_active_noop():
    """'active-noop' activation status → 'reused-cached'."""
    prov = {"activation_status": "active-noop", "used_last_known_good": False}
    state = _grype_provenance_state(prov)
    assert state["update_grype_db"] == "reused-cached"


def test_grype_provenance_state_last_known_good():
    """'last-known-good' activation status → 'reused-cached'."""
    prov = {"activation_status": "last-known-good", "used_last_known_good": False}
    state = _grype_provenance_state(prov)
    assert state["update_grype_db"] == "reused-cached"


def test_grype_provenance_state_custom_status():
    """Unknown/custom status string is passed through verbatim."""
    prov = {"activation_status": "stale-rejected"}
    state = _grype_provenance_state(prov)
    assert state["update_grype_db"] == "stale-rejected"


# ---------------------------------------------------------------------------
# _cve_provenance_state branches
# ---------------------------------------------------------------------------


def test_cve_provenance_state_non_dict_returns_unknown():
    """Non-dict provenance → update_cve_db=unknown."""
    state = _cve_provenance_state(None)
    assert state["update_cve_db"] == "unknown"


def test_cve_provenance_state_fresh_status():
    """'fresh' activation status is returned as-is."""
    prov = {"activation_status": "fresh"}
    state = _cve_provenance_state(prov)
    assert state["update_cve_db"] == "fresh"


def test_cve_provenance_state_active():
    """'active' → maps to 'fresh'."""
    prov = {"activation_status": "active"}
    state = _cve_provenance_state(prov)
    assert state["update_cve_db"] == "fresh"


def test_cve_provenance_state_last_known_good():
    """'last-known-good' → maps to 'lkg'."""
    prov = {"activation_status": "last-known-good"}
    state = _cve_provenance_state(prov)
    assert state["update_cve_db"] == "lkg"


def test_cve_provenance_state_used_lkg_flag():
    """used_last_known_good=True → maps to 'lkg'."""
    prov = {"activation_status": "", "used_last_known_good": True}
    state = _cve_provenance_state(prov)
    assert state["update_cve_db"] == "lkg"


def test_cve_provenance_state_version_from_cve_db_mtime(tmp_path: Path):
    """When selected_source is empty, cve.db mtime from last_known_good_audit is used."""
    prov = {
        "activation_status": "fresh",
        "selected_source": "",
        "last_known_good_audit": {"files": {"cve.db": {"mtime_utc": "2026-01-01T00:00:00Z"}}},
    }
    state = _cve_provenance_state(prov)
    assert "2026" in state["cve_db_version"]


# ---------------------------------------------------------------------------
# _overall_db_state — reused-cached path
# ---------------------------------------------------------------------------


def test_overall_db_state_fresh_or_reused(tmp_path: Path):
    """When one DB is 'refreshed-this-run' and another 'reused-cached',
    _overall_db_state should return 'fresh-or-reused'."""
    root = _seed_root(
        tmp_path / "artifacts",
        prov_grype={"activation_status": "active", "used_last_known_good": False},
        prov_cve={"activation_status": "last-known-good", "used_last_known_good": False},
        prov_trivy={"activation_status": "active", "used_last_known_good": False},
    )
    snapshot = derive(root)["db_snapshot"]
    # grype was "active" → "refreshed-this-run"; cve was "last-known-good" → "reused-cached"
    # When one DB refreshed and another reused, individual states are what matter.
    assert snapshot["grype_update_state"] == "refreshed-this-run"
    assert snapshot["cve_update_state"] == "lkg"


# ---------------------------------------------------------------------------
# _db_drift — reused-cached path (lines 316-318)
# ---------------------------------------------------------------------------


def test_db_drift_fresh_or_reused():
    """When states include both 'refreshed-this-run' and 'reused-cached',
    _db_drift should return 'fresh-or-reused'."""
    from pathlib import Path

    grype = {"update_grype_db": "refreshed-this-run"}
    cve = {"update_cve_db": "reused-cached"}
    trivy = {"update_trivy_db": "refreshed-this-run"}
    result = _db_drift(Path("."), grype, cve, trivy)
    assert result == "fresh-or-reused"


def test_db_drift_all_refreshed():
    """When all states are 'refreshed-this-run', returns 'refreshed-this-run'."""
    from pathlib import Path

    grype = {"update_grype_db": "refreshed-this-run"}
    cve = {"update_cve_db": "refreshed-this-run"}
    trivy = {"update_trivy_db": "refreshed-this-run"}
    result = _db_drift(Path("."), grype, cve, trivy)
    assert result == "refreshed-this-run"
