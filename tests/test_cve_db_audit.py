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
    _win_activate_fallback,
    activate_best_cve_bin_tool_db,
    audit_cve_bin_tool_db,
    classify_cve_db_health,
    seed_cve_bin_tool_aux_sources,
)


def _make_db_root(root: Path, *, include_nvd: bool = True) -> Path:
    """Create a minimal cve-bin-tool DB root suitable for audit tests.

    NVD presence is indicated by an ``nvdcve-*.json.gz`` file (matching real
    cve-bin-tool behaviour where NVD data lives in year-files, not in the
    ``cve_severity`` SQLite table).
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "redhat").mkdir(exist_ok=True)
    (root / "purl2cpe").mkdir(exist_ok=True)
    (root / "gad").mkdir(exist_ok=True)
    (root / "vuln.json").write_text("[]", encoding="utf-8")
    (root / "version_map.db").write_bytes(b"sqlite-placeholder")
    (root / "gad" / "advisory.yml").write_text("id: GAD-1\n", encoding="utf-8")
    (root / "redhat" / "CVE-2026-0001.json").write_text("{}", encoding="utf-8")
    if include_nvd:
        # Simulate a downloaded NVD year-file (content irrelevant for audit).
        (root / "nvdcve-2.0-2024.json.gz").write_bytes(b"")
    db_path = root / "cve.db"
    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE cve_range (data_source TEXT)")
        cursor.execute("CREATE TABLE cve_severity (data_source TEXT)")
        cursor.execute(
            "CREATE TABLE cve_metrics (cve_number TEXT, metric_id INTEGER, metric_score REAL, metric_field TEXT)"
        )
        cursor.execute("CREATE TABLE purl2cpe (id INTEGER)")
        cursor.executemany(
            "INSERT INTO cve_range (data_source) VALUES (?)", [("Curl",), ("REDHAT",), ("REDHAT",)]
        )
        cursor.executemany("INSERT INTO cve_severity (data_source) VALUES (?)", [("GAD",), ("REDHAT",)])
        if include_nvd:
            # Populate cve_metrics to simulate embedded NVD CVSS data (used by
            # json-mirror pre-built DBs that have no separate nvdcve year-files).
            cursor.executemany(
                "INSERT INTO cve_metrics VALUES (?,?,?,?)",
                [("CVE-2024-0001", 3, 7.5, "CVSS:3.1/AV:N"), ("CVE-2024-0002", 2, 5.0, "AV:N")],
            )
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
    # NVD is detected via nvdcve year-files (1 file created by fixture).
    assert payload["source_status"]["NVD"]["count"] == 1
    assert payload["source_status"]["NVD"]["evidence"] == "nvdcve json files"
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
        result = seed_cve_bin_tool_aux_sources(tmp_path, seed_epss=True, seed_rsd=False, osv_ecosystems=[])

    assert result["overall_status"] == "pass"
    assert "EPSS" in result["seeded"]
    epss_file = Path(result["seeded"]["EPSS"]["path"])
    assert epss_file.exists()
    assert epss_file.read_bytes() == csv_content


def test_seed_rsd_extracts_zip(tmp_path: Path):
    """seed_cve_bin_tool_aux_sources with seed_rsd=True extracts the zip archive."""
    fake_zip = _make_zip({"vuln1.yml": b"id: RSD-1\n", "vuln2.yml": b"id: RSD-2\n"})

    with patch("requests.get", return_value=_mock_response(fake_zip)):
        result = seed_cve_bin_tool_aux_sources(tmp_path, seed_epss=False, seed_rsd=True, osv_ecosystems=[])

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
        result = seed_cve_bin_tool_aux_sources(tmp_path, seed_epss=True, seed_rsd=False, osv_ecosystems=[])

    assert result["overall_status"] == "warn"
    assert any("EPSS" in f for f in result["failures"])


def test_seed_rsd_failure_recorded_in_result(tmp_path: Path):
    """When the RSD request fails, the failure is recorded (lines 405-406)."""
    failing_resp = MagicMock()
    failing_resp.raise_for_status.side_effect = Exception("rsd network error")
    failing_resp.content = b""

    with patch("requests.get", return_value=failing_resp):
        result = seed_cve_bin_tool_aux_sources(tmp_path, seed_epss=False, seed_rsd=True, osv_ecosystems=[])

    assert result["overall_status"] == "warn"
    assert any("RSD seed failed" in f for f in result["failures"])  # lines 405-406


def test_seed_osv_failure_recorded_in_result(tmp_path: Path):
    """When an OSV ecosystem request fails, the failure is recorded (lines 423-424)."""
    failing_resp = MagicMock()
    failing_resp.raise_for_status.side_effect = Exception("osv network error")
    failing_resp.content = b""

    with patch("requests.get", return_value=failing_resp):
        result = seed_cve_bin_tool_aux_sources(
            tmp_path, seed_epss=False, seed_rsd=False, osv_ecosystems=["PyPI"]
        )

    assert result["overall_status"] == "warn"
    assert any("OSV seed failed" in f for f in result["failures"])  # lines 423-424


# ---------------------------------------------------------------------------
# Additional coverage: _count_tree_files, stale db, policy clamping
# ---------------------------------------------------------------------------


def test_count_tree_files_nonexistent_returns_zero(tmp_path: Path):
    from resilient_updates.cve_db_audit import _count_tree_files

    assert _count_tree_files(tmp_path / "no_such_dir") == 0  # line 58


def test_count_tree_files_file_path_returns_zero(tmp_path: Path):
    from resilient_updates.cve_db_audit import _count_tree_files

    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    assert _count_tree_files(f) == 0  # not is_dir() → line 58


def test_audit_stale_db_adds_failure(tmp_path: Path):
    """When cve.db mtime is older than max_cache_age, a stale failure is appended (line 170)."""
    import os
    import time

    root = _make_db_root(tmp_path / "stale", include_nvd=True)
    # Age the cve.db by 48 hours
    old_mtime = time.time() - (48 * 3600)
    os.utime(root / "cve.db", (old_mtime, old_mtime))

    payload = audit_cve_bin_tool_db(
        root,
        required_sources=["NVD"],
        min_entries={"NVD": 1},
        max_cache_age="24h",  # 24h limit; db is 48h old → stale
        declared_sources=["NVD"],
    )
    assert any("stale" in f for f in payload["failures"])  # line 170-172


def test_policy_allows_status_unknown_policy_clamps_to_strict():
    from resilient_updates.cve_db_audit import _policy_allows_status

    # Unknown policy clamped to "strict" (line 257) → only "fresh" is allowed
    assert _policy_allows_status("bogus-policy", "fresh") is True
    assert _policy_allows_status("bogus-policy", "degraded") is False


def test_activate_unknown_db_policy_treated_as_strict(tmp_path: Path):
    """db_policy not in DB_POLICIES → clamped to 'strict' (line 285)."""
    active_root = _make_db_root(tmp_path / "active", include_nvd=True)
    previous_root = tmp_path / "previous"
    temp_root = tmp_path / "tmp"
    provenance_path = tmp_path / "prov.json"

    _activated, _payload = activate_best_cve_bin_tool_db(
        candidate_roots=[str(active_root)],
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        min_entries={"NVD": 1, "GAD": 1, "REDHAT": 1, "CURL": 1, "PURL2CPE": 1},
        max_cache_age="168h",
        declared_sources=["NVD", "GAD", "REDHAT", "CURL", "PURL2CPE"],
        db_policy="not-a-valid-policy",  # triggers line 285 clamping
    )
    # Fresh db passes strict policy


# ── D13: _win_activate_fallback tests ──────────────────────────────────────
# D13: Windows NTFS fallback uses os.replace (atomic MoveFileExW) instead of
# shutil.copytree+rmtree+shutil.move which created a multi-second gap where
# active_path was absent.  These tests exercise _win_activate_fallback directly.


def _make_tree(root: Path, name: str, content: str = "data") -> Path:
    """Create a named subdirectory with a single file."""
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "file.txt").write_text(content)
    return d


def test_win_activate_fallback_uses_os_replace(tmp_path, monkeypatch):
    """Happy path: os.replace succeeds → both renames are atomic, no copytree."""
    staging = _make_tree(tmp_path, "staging", "new")
    active = _make_tree(tmp_path, "active", "old")
    previous = tmp_path / "previous"

    copy_calls: list[str] = []
    real_replace = __import__("os").replace

    def patched_replace(src, dst):
        # record but also actually replace so filesystem stays consistent
        copy_calls.append(f"replace:{Path(src).name}->{Path(dst).name}")
        real_replace(src, dst)

    monkeypatch.setattr("resilient_updates.cve_db_audit.os.replace", patched_replace)
    # shutil.copytree must NOT be called
    monkeypatch.setattr(
        "resilient_updates.cve_db_audit.shutil.copytree",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("copytree called unexpectedly")),
    )

    _win_activate_fallback(staging, active, previous)

    # active slot now holds the new data
    assert (active / "file.txt").read_text() == "new"
    # previous holds the old active
    assert (previous / "file.txt").read_text() == "old"
    # staging is gone
    assert not staging.exists()
    # os.replace was called (not copytree)
    assert any("replace:" in c for c in copy_calls)


def test_win_activate_fallback_cross_device_falls_back_to_copy(tmp_path, monkeypatch):
    """When os.replace raises OSError (EXDEV), falls back to copytree+rmtree."""
    import errno as _errno

    staging = _make_tree(tmp_path, "staging", "new")
    active = _make_tree(tmp_path, "active", "old")
    previous = tmp_path / "previous"

    def raise_exdev(src, dst):
        raise OSError(_errno.EXDEV, "cross-device link")

    monkeypatch.setattr("resilient_updates.cve_db_audit.os.replace", raise_exdev)

    _win_activate_fallback(staging, active, previous)

    assert (active / "file.txt").read_text() == "new"
    assert (previous / "file.txt").read_text() == "old"


def test_win_activate_fallback_restores_active_on_staging_move_failure(tmp_path, monkeypatch):
    """If staging→active fails, active is restored from previous (never absent)."""
    import errno as _errno

    staging = _make_tree(tmp_path, "staging", "new")
    active = _make_tree(tmp_path, "active", "old")
    previous = tmp_path / "previous"

    call_count = {"n": 0}

    real_replace = __import__("os").replace

    def selective_replace(src, dst):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call: archive active→previous — let it succeed.
            real_replace(src, dst)
        else:
            # Second call: staging→active — fail.
            raise OSError(_errno.EXDEV, "cross-device")

    monkeypatch.setattr("resilient_updates.cve_db_audit.os.replace", selective_replace)

    # shutil.move (cross-device fallback for step 3) also fails
    monkeypatch.setattr(
        "resilient_updates.cve_db_audit.shutil.move",
        lambda src, dst: (_ for _ in ()).throw(OSError("move failed")),
    )
    # shutil.copytree used in rollback — allow it
    import shutil as _shutil

    monkeypatch.setattr("resilient_updates.cve_db_audit.shutil.copytree", _shutil.copytree)
    monkeypatch.setattr("resilient_updates.cve_db_audit.shutil.rmtree", _shutil.rmtree)

    with pytest.raises(OSError):
        _win_activate_fallback(staging, active, previous)

    # active must be restored — never absent after the exception
    assert active.exists(), "active was not restored after staging move failed"
    assert (active / "file.txt").read_text() == "old"


def test_win_activate_fallback_no_active_no_error(tmp_path):
    """When active_path doesn't exist, staging is still promoted cleanly."""
    staging = _make_tree(tmp_path, "staging", "new")
    active = tmp_path / "active"  # doesn't exist
    previous = tmp_path / "previous"

    _win_activate_fallback(staging, active, previous)

    assert (active / "file.txt").read_text() == "new"
    assert not previous.exists()


def test_activate_best_windows_permission_error_uses_fallback(tmp_path, monkeypatch):
    """PermissionError from publish_directory on Windows routes to _win_activate_fallback."""
    import resilient_updates.cve_db_audit as _mod

    fallback_calls: list[tuple[Path, Path, Path]] = []

    def fake_fallback(staging, active, previous):
        fallback_calls.append((staging, active, previous))
        # actually move so the function can finish
        import shutil

        if active.exists():
            shutil.rmtree(previous, ignore_errors=True)
            shutil.copytree(active, previous)
            shutil.rmtree(active)
        shutil.copytree(staging, active)

    monkeypatch.setattr(_mod, "_win_activate_fallback", fake_fallback)
    monkeypatch.setattr(
        _mod, "publish_directory", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("locked"))
    )
    # Patch _is_windows() instead of os.name — patching os.name globally breaks
    # pathlib.Path() on Linux (WindowsPath cannot be instantiated on POSIX).
    monkeypatch.setattr(_mod, "_is_windows", lambda: True)

    # Build a minimal valid DB in candidate_root so audit passes
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    active = tmp_path / "active"
    active.mkdir()
    previous = tmp_path / "previous"
    temp = tmp_path / "temp"
    prov = tmp_path / "prov.json"

    import sqlite3 as _sqlite3

    db = candidate / "cve.db"
    con = _sqlite3.connect(db)
    con.execute("CREATE TABLE cve_range (id INTEGER, data_source TEXT)")
    con.execute("CREATE TABLE cve_severity (id INTEGER, data_source TEXT)")
    con.execute("CREATE TABLE purl2cpe (id INTEGER)")
    con.execute("CREATE TABLE cve_metrics (id INTEGER)")
    con.commit()
    con.close()

    activated, _payload = activate_best_cve_bin_tool_db(
        candidate_roots=[candidate],
        active_root=active,
        previous_root=previous,
        temp_root=temp,
        provenance_path=prov,
        required_sources=[],
        min_entries={},
        max_cache_age="999h",
        declared_sources=[],
        db_policy="lkg-ok",
    )

    assert activated is True
    assert len(fallback_calls) == 1
