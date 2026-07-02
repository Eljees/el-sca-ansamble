from __future__ import annotations

import gzip
import io
import os
import shutil
import sqlite3
import zipfile

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from .artifact_store import ensure_directory
from .atomic_publish import publish_directory
from .config import parse_duration_hours
from .provenance import write_provenance

OBSERVABLE_CVE_SOURCES = {"NVD", "GAD", "REDHAT", "CURL", "OSV", "PURL2CPE", "EPSS", "RSD"}
UNOBSERVABLE_CVE_SOURCES: set[str] = set()
DB_POLICIES = {"strict", "degraded-ok", "lkg-ok"}


def _utc_from_mtime(path: Path) -> str | None:
    if not path.exists():
        return None
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def _age_hours(path: Path) -> float | None:
    if not path.exists():
        return None
    modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    return round((datetime.now(UTC) - modified).total_seconds() / 3600, 2)


def _path_info(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "exists": path.exists(),
        "is_dir": path.is_dir(),
        "size": None if not path.exists() or path.is_dir() else path.stat().st_size,
        "mtime_utc": _utc_from_mtime(path),
        "age_hours": _age_hours(path),
    }


def _count_tree_files(path: Path) -> int:
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


def _dir_info(path: Path) -> dict[str, Any]:
    return {
        **_path_info(path),
        "file_count": _count_tree_files(path) if path.exists() and path.is_dir() else 0,
    }


# Table names passed to the helpers below are always hardcoded literals supplied
# by this module (cve_range / cve_severity / purl2cpe) — never user input — so the
# f-string interpolation cannot be a SQL-injection vector (bandit B608 suppressed).
def _query_table_count(cursor: sqlite3.Cursor, table_name: str) -> int:
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")  # nosec B608
    row = cursor.fetchone()
    return int(row[0]) if row else 0


def _query_group_counts(cursor: sqlite3.Cursor, table_name: str) -> dict[str, int]:
    cursor.execute(
        f"SELECT data_source, COUNT(*) FROM {table_name} GROUP BY data_source"  # nosec B608
    )
    return {str(name): int(count) for name, count in cursor.fetchall()}


def _source_count(
    source: str,
    severity_counts: dict[str, int],
    range_counts: dict[str, int],
    purl2cpe_total: int,
    dir_infos: dict[str, dict[str, Any]],
    metrics_total: int = 0,
    db_root: Path | None = None,
) -> tuple[int | None, str]:
    source_upper = source.upper()
    if source_upper == "NVD":
        # cve-bin-tool does NOT store NVD data in cve_severity or cve_range.
        # NVD vulnerability ranges are read from nvdcve-YYYY.json.gz files at
        # scan time; NVD CVSS scores are stored in the cve_metrics table.
        # Use nvdcve file count as primary signal (present in json-nvd / api2
        # modes); fall back to cve_metrics total for json-mirror pre-built DBs
        # that embed NVD data without writing separate year-files.
        if db_root is not None:
            nvd_file_count = sum(1 for _ in db_root.glob("nvdcve*.json.gz"))
            if nvd_file_count > 0:
                return nvd_file_count, "nvdcve json files"
        # json-mirror embeds NVD CVSS in cve_metrics; treat non-zero total as
        # proof of NVD presence (real DBs have hundreds of thousands of rows).
        if metrics_total > 0:
            return metrics_total, "cve_metrics table"
        return 0, "nvdcve json files"
    if source_upper in {"GAD", "REDHAT"}:
        return severity_counts.get(source_upper, 0), "cve_severity"
    if source_upper == "CURL":
        return range_counts.get("Curl", 0), "cve_range"
    if source_upper == "OSV":
        return int(dir_infos["osv"]["file_count"]), "osv directory"
    if source_upper == "EPSS":
        return int(dir_infos["epss"]["file_count"]), "epss directory"
    if source_upper == "PURL2CPE":
        return purl2cpe_total, "purl2cpe table"
    if source_upper == "RSD":
        return int(dir_infos["rsd"]["file_count"]), "rsd directory"
    return None, "not directly observable"


def audit_cve_bin_tool_db(
    db_root: str | Path,
    required_sources: list[str],
    min_entries: dict[str, int],
    max_cache_age: str,
    declared_sources: list[str] | None = None,
) -> dict[str, Any]:
    root = Path(db_root)
    cve_db_path = root / "cve.db"
    version_map_path = root / "version_map.db"
    vuln_json_path = root / "vuln.json"
    dir_infos = {
        "epss": _dir_info(root / "epss"),
        "gad": _dir_info(root / "gad"),
        "osv": _dir_info(root / "osv"),
        "purl2cpe": _dir_info(root / "purl2cpe"),
        "redhat": _dir_info(root / "redhat"),
        "rsd": _dir_info(root / "rsd"),
    }
    files = {
        "cve.db": _path_info(cve_db_path),
        "version_map.db": _path_info(version_map_path),
        "vuln.json": _path_info(vuln_json_path),
        **dir_infos,
    }
    result: dict[str, Any] = {
        "db_root": str(root),
        "required_sources": required_sources,
        "declared_sources": declared_sources or [],
        "max_cache_age": max_cache_age,
        "files": files,
        "counts": {
            "cve_range_total": 0,
            "cve_severity_total": 0,
            "cve_metrics_total": 0,
            "purl2cpe_total": 0,
            "cve_range_by_source": {},
            "cve_severity_by_source": {},
        },
        "source_status": {},
        "failures": [],
        "warnings": [],
        "overall_status": "fail",
    }
    if not cve_db_path.exists():
        result["failures"].append("missing cve.db")
        return result

    try:
        with sqlite3.connect(cve_db_path) as connection:
            cursor = connection.cursor()
            result["counts"]["cve_range_total"] = _query_table_count(cursor, "cve_range")
            result["counts"]["cve_severity_total"] = _query_table_count(cursor, "cve_severity")
            result["counts"]["purl2cpe_total"] = _query_table_count(cursor, "purl2cpe")
            result["counts"]["cve_range_by_source"] = _query_group_counts(cursor, "cve_range")
            result["counts"]["cve_severity_by_source"] = _query_group_counts(cursor, "cve_severity")
            # cve_metrics stores NVD CVSS scores (metric_id-keyed, no data_source column)
            try:
                result["counts"]["cve_metrics_total"] = _query_table_count(cursor, "cve_metrics")
            except Exception:
                result["counts"]["cve_metrics_total"] = 0
    except sqlite3.DatabaseError as exc:
        result["failures"].append(f"sqlite error: {exc}")
        return result

    max_age_hours = parse_duration_hours(max_cache_age)
    core_age_hours = files["cve.db"]["age_hours"]
    if core_age_hours is not None and core_age_hours > max_age_hours:
        result["failures"].append(
            f"cve.db is stale: age_hours={core_age_hours} exceeds max_cache_age={max_age_hours}"
        )

    severity_counts = result["counts"]["cve_severity_by_source"]
    range_counts = result["counts"]["cve_range_by_source"]
    purl2cpe_total = int(result["counts"]["purl2cpe_total"])
    metrics_total = int(result["counts"]["cve_metrics_total"])
    declared = declared_sources or sorted(OBSERVABLE_CVE_SOURCES | UNOBSERVABLE_CVE_SOURCES)

    for source in declared:
        count, evidence = _source_count(
            source,
            severity_counts,
            range_counts,
            purl2cpe_total,
            dir_infos,
            metrics_total=metrics_total,
            db_root=root,
        )
        observable = source.upper() in OBSERVABLE_CVE_SOURCES
        min_count = int(min_entries.get(source.upper(), min_entries.get(source, 1 if observable else 0)))
        present = (count or 0) >= min_count if observable else None
        status = "ok"
        reason = None
        if not observable:
            status = "unobservable"
            reason = "no stable on-disk count is available for this source"
        elif count is None or count < min_count:
            status = "failed"
            reason = f"count {count or 0} is below min_entries {min_count}"
            if source in required_sources:
                result["failures"].append(f"{source} count {count or 0} is below minimum {min_count}")
            else:
                result["warnings"].append(f"{source} count {count or 0} is below minimum {min_count}")
        result["source_status"][source] = {
            "observable": observable,
            "present": present,
            "count": count,
            "min_entries": min_count,
            "status": status,
            "evidence": evidence,
            "reason": reason,
        }

    missing_required = [
        item for item in required_sources if result["source_status"].get(item, {}).get("status") != "ok"
    ]
    if missing_required:
        result["failures"].append(f"required sources failed audit: {', '.join(missing_required)}")

    result["overall_status"] = "pass" if not result["failures"] else "fail"
    return result


def classify_cve_db_health(
    audit_payload: dict[str, Any],
    required_sources: list[str],
) -> tuple[str, dict[str, Any]]:
    """Classify audited DB health into fresh/degraded/failed."""
    required_upper = {item.upper() for item in required_sources}
    source_status = audit_payload.get("source_status") or {}
    if audit_payload.get("overall_status") != "pass":
        return "failed", {"missing_required": sorted(required_upper), "missing_optional": []}

    missing_required: list[str] = []
    missing_optional: list[str] = []

    for source_name, payload in source_status.items():
        if not isinstance(payload, dict):
            continue
        if payload.get("observable") is not True:
            continue
        if payload.get("status") == "ok":
            continue
        source_upper = str(source_name).upper()
        if source_upper in required_upper:
            missing_required.append(source_upper)
        else:
            missing_optional.append(source_upper)

    if missing_required:
        return "failed", {
            "missing_required": sorted(set(missing_required)),
            "missing_optional": sorted(set(missing_optional)),
        }
    if missing_optional:
        return "degraded", {
            "missing_required": [],
            "missing_optional": sorted(set(missing_optional)),
        }
    return "fresh", {"missing_required": [], "missing_optional": []}


def _is_windows() -> bool:
    """Return True when running on Windows.  Extracted so tests can patch it without
    touching ``os.name`` globally (patching ``os.name`` breaks ``Path()`` on Linux)."""
    return os.name == "nt"


def _win_activate_fallback(staging_dir: Path, active_path: Path, previous_path: Path) -> None:
    """Windows NTFS fallback when ``publish_directory`` raises ``PermissionError``.

    Replaces the original ``shutil.copytree + rmtree + shutil.move`` sequence
    (D13) with ``os.replace`` (maps to ``MoveFileExW`` on NTFS), which is
    atomic for same-volume moves.  This eliminates the multi-second gap during
    which ``active_path`` was absent while a 6 GB DB was being copied.

    Sequence
    --------
    1. Clear *previous_path* slot so ``os.replace`` can use it.
    2. Archive *active_path* → *previous_path* atomically (same-volume) or via
       copy+rmtree (cross-device fallback).
    3. Promote *staging_dir* → *active_path* atomically (same-volume) or via
       ``shutil.move`` (cross-device fallback).

    On any failure in step 3, *active_path* is restored from *previous_path*
    so the DB directory is never left absent.
    """
    # Step 1: clear previous slot — os.replace requires dst to be absent on Windows.
    if previous_path.exists():
        shutil.rmtree(previous_path)

    # Step 2: archive active → previous (atomic MoveFileExW, or copy+rmtree cross-device).
    active_archived = False
    if active_path.exists():
        try:
            os.replace(active_path, previous_path)
        except OSError:
            # Cross-device: fall back to copy then remove (non-atomic, but rare).
            shutil.copytree(active_path, previous_path)
            shutil.rmtree(active_path)
        active_archived = True

    # Step 3: promote staging → active (atomic MoveFileExW, or shutil.move cross-device).
    try:
        try:
            os.replace(staging_dir, active_path)
        except OSError:
            # Cross-device: shutil.move tries os.rename first, then copy+unlink.
            shutil.move(str(staging_dir), str(active_path))
    except Exception:
        # Roll back: restore active from previous so the DB is never absent.
        if active_archived and previous_path.exists() and not active_path.exists():
            try:
                os.replace(previous_path, active_path)
            except OSError:
                shutil.copytree(previous_path, active_path)
        raise


def _policy_allows_status(policy: str, status: str) -> bool:
    if policy not in DB_POLICIES:
        policy = "strict"
    allowed = {
        "strict": {"fresh"},
        "degraded-ok": {"fresh", "degraded"},
        "lkg-ok": {"fresh", "degraded"},
    }
    return status in allowed[policy]


def activate_best_cve_bin_tool_db(
    candidate_roots: list[str | Path],
    active_root: str | Path,
    previous_root: str | Path,
    temp_root: str | Path,
    provenance_path: str | Path,
    required_sources: list[str],
    min_entries: dict[str, int],
    max_cache_age: str,
    declared_sources: list[str] | None = None,
    db_policy: str = "strict",
) -> tuple[bool, dict[str, Any]]:
    audits: list[dict[str, Any]] = []
    selected_root: Path | None = None
    selected_audit: dict[str, Any] | None = None
    selected_health_status: str = "failed"
    selected_health_details: dict[str, Any] = {"missing_required": [], "missing_optional": []}

    if db_policy not in DB_POLICIES:
        db_policy = "strict"

    for candidate in candidate_roots:
        audit = audit_cve_bin_tool_db(
            candidate, required_sources, min_entries, max_cache_age, declared_sources
        )
        audits.append(audit)
        health_status, health_details = classify_cve_db_health(audit, required_sources)
        if _policy_allows_status(db_policy, health_status):
            selected_root = Path(candidate)
            selected_audit = audit
            selected_health_status = health_status
            selected_health_details = health_details
            break

    active_path = Path(active_root)
    previous_path = Path(previous_root)
    temp_parent = ensure_directory(temp_root)
    payload: dict[str, Any] = {
        "tool": "cve-bin-tool",
        "artifact_type": "cve-bin-tool-db",
        "selected_source": str(selected_root) if selected_root else None,
        "attempted_sources": [item["db_root"] for item in audits],
        "failures": [
            {
                "db_root": item["db_root"],
                "overall_status": item["overall_status"],
                "failures": item["failures"],
            }
            for item in audits
            if item["overall_status"] != "pass"
        ],
        "used_last_known_good": False,
        "db_policy": db_policy,
        "selected_health_status": selected_health_status,
        "selected_health_details": selected_health_details,
        "activation_status": "failed",
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }
    if not selected_root or not selected_audit:
        lkg = audit_cve_bin_tool_db(
            active_path, required_sources, min_entries, max_cache_age, declared_sources
        )
        lkg_status, lkg_details = classify_cve_db_health(lkg, required_sources)
        payload["last_known_good_audit"] = lkg
        payload["last_known_good_status"] = lkg_status
        payload["last_known_good_details"] = lkg_details
        if db_policy == "lkg-ok" and lkg_status in {"fresh", "degraded"}:
            payload["used_last_known_good"] = True
            payload["activation_status"] = "lkg"
            write_provenance(Path(provenance_path), payload)
            return False, payload
        write_provenance(Path(provenance_path), payload)
        return False, payload

    if selected_root.resolve() == active_path.resolve():
        payload["activation_status"] = selected_health_status
        payload["selected_audit"] = selected_audit
        write_provenance(Path(provenance_path), payload)
        return True, payload

    staging_dir = temp_parent / f"run-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    shutil.copytree(selected_root, staging_dir)
    try:
        publish_directory(staging_dir, active_path, previous_path)
    except PermissionError:
        if not _is_windows():
            raise
        _win_activate_fallback(staging_dir, active_path, previous_path)
    payload["activation_status"] = selected_health_status
    payload["selected_audit"] = selected_audit
    write_provenance(Path(provenance_path), payload)
    return True, payload


def seed_cve_bin_tool_aux_sources(
    db_root: str | Path,
    *,
    seed_epss: bool,
    seed_rsd: bool,
    osv_ecosystems: list[str],
    timeout: int = 120,
) -> dict[str, Any]:
    root = ensure_directory(db_root)
    result: dict[str, Any] = {"db_root": str(root), "seeded": {}, "failures": []}

    if seed_epss:
        epss_dir = ensure_directory(root / "epss")
        epss_target = epss_dir / "epss_scores-current.csv"
        try:
            response = requests.get("https://epss.cyentia.com/epss_scores-current.csv.gz", timeout=timeout)
            response.raise_for_status()
            epss_target.write_bytes(gzip.decompress(response.content))
            result["seeded"]["EPSS"] = {"path": str(epss_target), "size": epss_target.stat().st_size}
        except Exception as exc:
            result["failures"].append(f"EPSS seed failed: {exc}")

    if seed_rsd:
        rsd_dir = ensure_directory(root / "rsd")
        try:
            response = requests.get(
                "https://gitlab.com/vulnerabilities1/vulnerabities/-/archive/main/vulnerabities-main.zip",
                timeout=timeout,
            )
            response.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                archive.extractall(rsd_dir)
            result["seeded"]["RSD"] = {"path": str(rsd_dir), "file_count": _count_tree_files(rsd_dir)}
        except Exception as exc:
            result["failures"].append(f"RSD seed failed: {exc}")

    if osv_ecosystems:
        osv_dir = ensure_directory(root / "osv")
        seeded_ecosystems: list[dict[str, Any]] = []
        for ecosystem in osv_ecosystems:
            try:
                response = requests.get(
                    f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
                    timeout=timeout,
                )
                response.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                    archive.extractall(osv_dir)
                seeded_ecosystems.append(
                    {"ecosystem": ecosystem, "files_after_extract": _count_tree_files(osv_dir)}
                )
            except Exception as exc:
                result["failures"].append(f"OSV seed failed for {ecosystem}: {exc}")
        if seeded_ecosystems:
            result["seeded"]["OSV"] = seeded_ecosystems

    result["overall_status"] = "pass" if not result["failures"] else "warn"
    return result
