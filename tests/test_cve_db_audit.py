from __future__ import annotations

import gzip
import io
import json
import sqlite3
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from resilient_updates.cve_db_audit import (
    activate_best_cve_bin_tool_db,
    audit_cve_bin_tool_db,
    classify_cve_db_health,
    seed_cve_bin_tool_aux_sources,
)


def _make_db_root(root: Path, *, include_nvd: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "redhat").mkdir(exist_ok=True)
    (root / "purl2cpe").mkdir(exist_ok=True)
    (root / "gad").mkdir(exist_ok=True)
    (root / "vuln.json").write_text("[]", encoding="utf-8")
    (root / "version_map.db").write_bytes(b"sqlite-placeholder")
    (root / "gad" / "advisory.yml").write_text("id: GAD-1\n", encoding="utf-8")
    (root / "redhat" / "CVE-2026-0001.json").write_text("{}", encoding="utf-8")
    db_path = root / "cve.db"
    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE cve_range (data_source TEXT)")
        cursor.execute("CREATE TABLE cve_severity (data_source TEXT)")
        cursor.execute("CREATE TABLE purl2cpe (id INTEGER)")
        cursor.executemany(
            "INSERT INTO cve_range (data_source) VALUES (?)", [("Curl",), ("REDHAT",), ("REDHAT",)]
        )
        cursor.executemany("INSERT INTO cve_severity (data_source) VALUES (?)", [("GAD",), ("REDHAT",)])
        if include_nvd:
            cursor.executemany("INSERT INTO cve_severity (data_source) VALUES (?)", [("NVD",), ("NVD",)])
        cursor.executemany("INSERT INTO purl2cpe (id) VALUES (?)", [(1,), (2,), (3,)])
        connection.commit()
    return root


def test_audit_fails_when_nvd_is_missing(tmp_path: Path):
    root = _make_db_root(tmp_path / "broken", include_nvd=False)
    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
    )
    assert payload["overall_status"] == "fail"
    assert payload["source_status"]["NVD"]["status"] == "failed"
    assert any("NVD" in item for item in payload["failures"])


def test_audit_passes_with_required_sources(tmp_path: Path):
    root = _make_db_root(tmp_path / "healthy", include_nvd=True)
    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
    )
    assert payload["overall_status"] == "pass"
    assert payload["source_status"]["NVD"]["count"] == 2
    assert payload["source_status"]["PURL2CPE"]["count"] == 3


def test_activate_falls_back_to_second_candidate(tmp_path: Path):
    bad_root = _make_db_root(tmp_path / "bad", include_nvd=False)
    good_root = _make_db_root(tmp_path / "good", include_nvd=True)
    active_root = tmp_path / "active"
    previous_root = tmp_path / "previous"
    temp_root = tmp_path / "tmp"
    provenance_path = tmp_path / "prov.json"
    activated, payload = activate_best_cve_bin_tool_db(
        candidate_roots=[str(bad_root), str(good_root)],
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
    )
    assert activated is True
    assert payload["selected_source"] == str(good_root)
    assert (active_root / "cve.db").exists()
    saved = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert saved["activation_status"] == "fresh"


def test_classify_reports_degraded_when_optional_source_missing(tmp_path: Path):
    root = _make_db_root(tmp_path / "degraded", include_nvd=True)
    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1, "OSV": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE", "OSV"],
    )
    status, details = classify_cve_db_health(payload, ["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"])
    assert status == "degraded"
    assert "OSV" in details["missing_optional"]


def test_strict_policy_rejects_degraded_candidate(tmp_path: Path):
    root = _make_db_root(tmp_path / "strict", include_nvd=True)
    active_root = tmp_path / "active"
    previous_root = tmp_path / "previous"
    temp_root = tmp_path / "tmp"
    provenance_path = tmp_path / "prov-strict.json"
    activated, payload = activate_best_cve_bin_tool_db(
        candidate_roots=[str(root)],
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1, "OSV": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE", "OSV"],
        db_policy="strict",
    )
    assert activated is False
    assert payload["activation_status"] == "failed"


def test_lkg_policy_allows_fallback(tmp_path: Path):
    stale_candidate = _make_db_root(tmp_path / "candidate", include_nvd=False)
    del stale_candidate  # shape only; active root carries the usable LKG
    active_root = _make_db_root(tmp_path / "active", include_nvd=True)
    previous_root = tmp_path / "previous"
    temp_root = tmp_path / "tmp"
    provenance_path = tmp_path / "prov-lkg.json"

    activated, payload = activate_best_cve_bin_tool_db(
        candidate_roots=[str(tmp_path / "candidate")],
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        db_policy="lkg-ok",
    )
    assert activated is False
    assert payload["used_last_known_good"] is True
    assert payload["activation_status"] == "lkg"


# ---------------------------------------------------------------------------
# _source_count — EPSS, RSD and unknown source paths (lines 100-105)
# ---------------------------------------------------------------------------


def _make_db_root_with_epss_rsd(root: Path) -> Path:
    """Like _make_db_root but also seeds epss/ and rsd/ directories."""
    _make_db_root(root)
    epss_dir = root / "epss"
    epss_dir.mkdir(exist_ok=True)
    (epss_dir / "epss_scores-current.csv").write_text("cve_id,score\n", encoding="utf-8")
    rsd_dir = root / "rsd"
    rsd_dir.mkdir(exist_ok=True)
    (rsd_dir / "advisory.yml").write_text("id: RSD-1\n", encoding="utf-8")
    return root


def test_audit_reports_epss_source_via_file_count(tmp_path: Path):
    """When EPSS is declared, its count comes from the epss/ directory file count."""
    root = _make_db_root_with_epss_rsd(tmp_path / "db")

    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD", "GAD"],
        min_entries={"NVD": 1, "GAD": 1, "EPSS": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "EPSS"],
    )

    epss_status = payload["source_status"]["EPSS"]
    assert epss_status["count"] == 1  # one file in epss/
    assert epss_status["evidence"] == "epss directory"


def test_audit_reports_rsd_source_via_file_count(tmp_path: Path):
    """When RSD is declared, its count comes from the rsd/ directory file count."""
    root = _make_db_root_with_epss_rsd(tmp_path / "db")

    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD"],
        min_entries={"NVD": 1, "RSD": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "RSD"],
    )

    rsd_status = payload["source_status"]["RSD"]
    assert rsd_status["count"] == 1  # one file in rsd/
    assert rsd_status["evidence"] == "rsd directory"


def test_audit_unknown_source_not_directly_observable(tmp_path: Path):
    """A declared source that is NOT in OBSERVABLE_CVE_SOURCES gets status 'unobservable'."""
    root = _make_db_root(tmp_path / "db")

    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD"],
        min_entries={"NVD": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "UNKNOWN_SOURCE_XYZ"],
    )

    status = payload["source_status"].get("UNKNOWN_SOURCE_XYZ", {})
    assert status["status"] == "unobservable"


# ---------------------------------------------------------------------------
# audit_cve_bin_tool_db — sqlite error (lines 163-165)
# ---------------------------------------------------------------------------


def test_audit_handles_corrupt_cve_db(tmp_path: Path):
    """A corrupt cve.db (sqlite.DatabaseError) is caught and returned as failure."""
    root = _make_db_root(tmp_path / "db")
    (root / "cve.db").write_bytes(b"not-a-sqlite-db")

    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD"],
        min_entries={"NVD": 1},
        max_cache_age="168h",
    )

    assert payload["overall_status"] == "fail"
    assert any("sqlite error" in f for f in payload["failures"])


# ---------------------------------------------------------------------------
# classify_cve_db_health — non-dict source_status entry (line 231)
# ---------------------------------------------------------------------------


def test_classify_cve_db_health_skips_non_dict_source_entries():
    """A non-dict entry in source_status must be ignored (continue) without crashing."""
    audit_payload = {
        "overall_status": "pass",
        "source_status": {
            "NVD": "broken-value",  # not a dict — must be skipped
            "GAD": {"observable": True, "status": "ok"},
        },
    }
    status, _details = classify_cve_db_health(audit_payload, ["NVD", "GAD"])
    assert status == "fresh"  # GAD is ok; NVD entry is skipped


def test_classify_cve_db_health_skips_unobservable_source():
    """A source with observable=False is silently skipped (not counted as missing)."""
    audit_payload = {
        "overall_status": "pass",
        "source_status": {
            "NVD": {"observable": True, "status": "ok"},
            "RSD": {"observable": False, "status": "unobservable"},  # skipped
        },
    }
    status, _details = classify_cve_db_health(audit_payload, ["NVD"])
    assert status == "fresh"


def test_classify_cve_db_health_failed_when_required_missing():
    """An observable required source with status != 'ok' must cause 'failed' return."""
    audit_payload = {
        "overall_status": "pass",
        "source_status": {
            "NVD": {"observable": True, "status": "failed"},
        },
    }
    status, details = classify_cve_db_health(audit_payload, ["NVD"])
    assert status == "failed"
    assert "NVD" in details["missing_required"]


# ---------------------------------------------------------------------------
# _activate — early-return when selected == active (lines 341-344)
# ---------------------------------------------------------------------------


def test_activate_returns_true_when_selected_is_already_active(tmp_path: Path):
    """When the best candidate is the same path as active_root, no copy is needed."""
    # Seed the active root — it's also the candidate.
    active_root = _make_db_root(tmp_path / "active", include_nvd=True)
    previous_root = tmp_path / "previous"
    temp_root = tmp_path / "tmp"
    provenance_path = tmp_path / "prov.json"

    activated, payload = activate_best_cve_bin_tool_db(
        candidate_roots=[str(active_root)],  # candidate IS the active path
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
    )

    # Should report activated=True immediately without doing a copy.
    assert activated is True
    assert payload["activation_status"] in ("fresh", "degraded")


# ---------------------------------------------------------------------------
# seed_cve_bin_tool_aux_sources — EPSS + RSD + OSV with mocked requests
# ---------------------------------------------------------------------------


def _make_gz(content: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(content)
    return buf.getvalue()


def _make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _mock_response(content: bytes, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.smoke
def test_seed_epss_writes_csv(tmp_path: Path):
    """seed_cve_bin_tool_aux_sources with seed_epss=True writes epss CSV."""
    csv_content = b"cve_id,epss\nCVE-2024-0001,0.5\n"
    fake_gz = _make_gz(csv_content)

    with patch("requests.get", return_value=_mock_response(fake_gz)):
        result = seed_cve_bin_tool_aux_sources(
            tmp_path, seed_epss=True, seed_rsd=False, osv_ecosystems=[]
        )

    assert result["overall_status"] == "pass"
    assert "EPSS" in result["seeded"]
    epss_file = Path(result["seeded"]["EPSS"]["path"])
    assert epss_file.exists()
    assert epss_file.read_bytes() == csv_content


def test_seed_rsd_extracts_zip(tmp_path: Path):
    """seed_cve_bin_tool_aux_sources with seed_rsd=True extracts the zip archive."""
    fake_zip = _make_zip({"vuln1.yml": b"id: RSD-1\n", "vuln2.yml": b"id: RSD-2\n"})

    with patch("requests.get", return_value=_mock_response(fake_zip)):
        result = seed_cve_bin_tool_aux_sources(
            tmp_path, seed_epss=False, seed_rsd=True, osv_ecosystems=[]
        )

    assert result["overall_status"] == "pass"
    assert "RSD" in result["seeded"]
    assert result["seeded"]["RSD"]["file_count"] == 2


def test_seed_osv_extracts_per_ecosystem(tmp_path: Path):
    """seed_cve_bin_tool_aux_sources with osv_ecosystems seeds each ecosystem."""
    fake_zip = _make_zip({"CVE-2024-0001.json": b"{}"})

    with patch("requests.get", return_value=_mock_response(fake_zip)):
        result = seed_cve_bin_tool_aux_sources(
            tmp_path, seed_epss=False, seed_rsd=False, osv_ecosystems=["PyPI", "Go"]
        )

    assert result["overall_status"] == "pass"
    assert "OSV" in result["seeded"]
    assert len(result["seeded"]["OSV"]) == 2


def test_seed_epss_failure_recorded_in_result(tmp_path: Path):
    """When the EPSS request fails, the failure is recorded and overall is 'warn'."""
    failing_resp = MagicMock()
    failing_resp.raise_for_status.side_effect = Exception("network error")
    failing_resp.content = b""

    with patch("requests.get", return_value=failing_resp):
        result = seed_cve_bin_tool_aux_sources(
            tmp_path, seed_epss=True, seed_rsd=False, osv_ecosystems=[]
        )

    assert result["overall_status"] == "warn"
    assert any("EPSS" in f for f in result["failures"])
