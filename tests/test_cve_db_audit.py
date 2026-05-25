from __future__ import annotations

from pathlib import Path
import json
import sqlite3

from resilient_updates.cve_db_audit import (
    activate_best_cve_bin_tool_db,
    audit_cve_bin_tool_db,
    classify_cve_db_health,
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
        cursor.executemany("INSERT INTO cve_range (data_source) VALUES (?)", [("Curl",), ("REDHAT",), ("REDHAT",)])
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
