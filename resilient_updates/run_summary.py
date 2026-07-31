"""Derive run-summary metadata from on-disk scan artifacts.

Historically the pipeline expected four sidecar files to live in
``artifacts/`` and feed the header of the final Markdown report:

- ``summary.json``     — counts, policy decision, update intent
- ``status.json``      — tool_failures, db_drift
- ``run_manifest.json``— input sha256, db_snapshot id
- ``db_snapshot.json`` — snapshot id of the DB layer used

No stage ever wrote them, so the header showed ``UNKNOWN`` for everything.
This module computes the same data from artefacts that DO exist:

- ``artifacts/sbom/syft.json``         — component count
- ``artifacts/reports/grype/report.json`` — match count
- ``artifacts/reports/trivy/report.json``
- ``artifacts/reports/cve-bin-tool/report.json``
  (+ optional ``timeout.flag`` sibling)
- ``artifacts/extracted/current/extraction_manifest.json`` — input sha256
- ``artifacts/provenance/grype.json``  — selected source / built / checksum
- ``artifacts/provenance/cve-bin-tool-db.json`` — activation status / audit

It produces in-memory dicts (used by ``reporting.build_report`` as a
fallback) AND writes them to disk so external tooling has a stable
machine-readable record per run.  All file I/O is best-effort: a missing
input never raises, the corresponding field is left blank instead.
"""

from __future__ import annotations

import json

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
from typing import Any

from ._io import (
    hash_triple as _hash_path,
    hash_triple_dir as _hash_triple_dir,
    read_json as _read_json,
    short_hash as _short_hash,
)

# ---------------------------------------------------------------------------
# Low-level helpers
#
# `_read_json`, `_short_hash` and `_hash_path` used to be inlined here; they
# now come from resilient_updates._io to remove the duplication across
# reporting.py / run_summary.py / extractor.py / scanner_diff.py.
# See docs/audit/20-architecture.md §1.
# ---------------------------------------------------------------------------


def _count_list(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


# ---------------------------------------------------------------------------
# Field derivations
# ---------------------------------------------------------------------------


def _component_count(syft: Any) -> int:
    if not isinstance(syft, dict):
        return 0
    return _count_list(syft.get("artifacts"))


def _grype_match_count(grype: Any) -> int:
    if not isinstance(grype, dict):
        return 0
    return _count_list(grype.get("matches"))


def _trivy_match_count(trivy: Any) -> int:
    if not isinstance(trivy, dict):
        return 0
    total = 0
    for result in trivy.get("Results") or []:
        total += _count_list(result.get("Vulnerabilities"))
    return total


def _cve_bin_tool_count(cve: Any) -> int:
    if isinstance(cve, list):
        return len(cve)
    return 0


def _top_level_input_items(extraction_manifest: Any) -> list[dict[str, Any]]:
    if not isinstance(extraction_manifest, dict):
        return []
    items = extraction_manifest.get("items") or []
    if not isinstance(items, list):
        return []
    dict_items = [item for item in items if isinstance(item, dict)]
    top_level = [item for item in dict_items if item.get("depth") == 0]
    return top_level or dict_items


def _input_sha256(extraction_manifest: Any) -> str | None:
    items = _top_level_input_items(extraction_manifest)
    if not items:
        return None
    # Prefer depth=0 items so nested archives discovered during extraction
    # do not overwrite the identity of the original input artifact.
    if len(items) == 1:
        digest = str(items[0].get("sha256") or "")
        return digest or None
    parts = [str(item.get("sha256") or "") for item in items if isinstance(item, dict)]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return f"multi:{_short_hash(*parts)}"


def _input_hashes(extraction_manifest: Any) -> dict[str, str]:
    items = _top_level_input_items(extraction_manifest)
    if len(items) != 1 or not isinstance(items[0], dict):
        return {}
    item = items[0]
    recorded = {key: str(item.get(key)) for key in ("md5", "sha1", "sha256") if item.get(key)}
    # A "rich" record from the current extractor already carries sha1/md5 —
    # trust it and skip re-hashing (the recorded ``archive`` is a container
    # path that would not resolve on the host anyway).
    if recorded.get("sha1") or recorded.get("md5"):
        return recorded
    # Older / sha256-only manifests: re-hash the actual file when reachable to
    # recover the full md5+sha1+sha256 triple.
    archive = str(item.get("archive") or "").strip()
    if archive:
        path = Path(archive)
        if path.exists() and path.is_file():
            try:
                return _hash_path(path)
            except OSError:
                pass
    # Last resort: whatever was recorded (possibly just sha256, possibly {}).
    return recorded


def _target_hashes(base: Path, extraction_manifest: Any) -> dict[str, str]:
    """md5/sha1/sha256 of what the scanners actually ran on.

    The pipeline re-points every scanner at ``extracted/current`` (the
    unpacked tree), so that directory *is* the final target — hash its content
    once (stable across platforms).  If nothing was extracted (the archive was
    scanned directly), fall back to the input archive's digests so the field is
    never a bare UNKNOWN.
    """
    extracted = base / "extracted" / "current"
    try:
        if extracted.is_dir() and any(p.is_file() for p in extracted.rglob("*")):
            return _hash_triple_dir(extracted)
    except OSError:
        pass
    return _input_hashes(extraction_manifest)


def _grype_provenance_state(prov_grype: Any) -> dict[str, str]:
    """Map a ``provenance/grype.json`` to coarse update-state fields."""
    if not isinstance(prov_grype, dict):
        return {
            "update_grype_db": "unknown",
            "grype_built": "",
            "grype_db_version": "",
            "grype_db_source": "",
            "grype_updated_at": "",
        }
    status = str(prov_grype.get("activation_status") or "").strip()
    used_lkg = bool(prov_grype.get("used_last_known_good"))
    if status == "active":
        update_state = "refreshed-this-run"
    elif status in {"active-noop", "last-known-good"} or used_lkg:
        update_state = "reused-cached"
    elif status:
        update_state = status
    else:
        update_state = "unknown"
    built = ""
    meta = prov_grype.get("freshness_metadata")
    if isinstance(meta, dict):
        built = str(meta.get("built") or "")
    checksum = str(prov_grype.get("checksum") or "")
    selected_source = prov_grype.get("selected_source") or {}
    if isinstance(selected_source, dict):
        selected_source = selected_source.get("name") or selected_source.get("url") or ""
    return {
        "update_grype_db": update_state,
        "grype_built": built,
        "grype_db_version": checksum,
        "grype_db_source": str(selected_source or ""),
        "grype_updated_at": str(prov_grype.get("timestamp_utc") or ""),
    }


def _cve_provenance_state(prov_cve: Any) -> dict[str, str]:
    if not isinstance(prov_cve, dict):
        return {
            "update_cve_db": "unknown",
            "cve_db_version": "",
            "cve_db_source": "",
            "cve_updated_at": "",
        }
    status = str(prov_cve.get("activation_status") or "").strip()
    used_lkg = bool(prov_cve.get("used_last_known_good"))
    if status in {"fresh", "degraded", "lkg", "failed"}:
        update_state = status
    elif status == "active" or status == "active-noop":
        update_state = "fresh"
    elif status == "last-known-good" or used_lkg:
        update_state = "lkg"
    elif status:
        update_state = status
    else:
        update_state = "unknown"
    selected_source = str(prov_cve.get("selected_source") or "")
    version = selected_source
    audit = prov_cve.get("last_known_good_audit") or {}
    cve_db_file = (audit.get("files") or {}).get("cve.db") if isinstance(audit, dict) else {}
    if not version and isinstance(cve_db_file, dict):
        version = str(cve_db_file.get("mtime_utc") or "")
    return {
        "update_cve_db": update_state,
        "cve_db_version": version,
        "cve_db_source": selected_source,
        "cve_updated_at": str(prov_cve.get("timestamp_utc") or ""),
    }


def _trivy_provenance_state(prov_trivy: Any) -> dict[str, str]:
    if not isinstance(prov_trivy, dict):
        return {
            "update_trivy_db": "unknown",
            "trivy_db_version": "",
            "trivy_db_source": "",
            "trivy_updated_at": "",
        }
    status = str(prov_trivy.get("activation_status") or "").strip()
    update_state = status or "unknown"
    selected_source = prov_trivy.get("selected_source") or {}
    if isinstance(selected_source, dict):
        selected_source = selected_source.get("name") or selected_source.get("url") or ""
    return {
        "update_trivy_db": update_state,
        "trivy_db_version": str(prov_trivy.get("artifact_type") or ""),
        "trivy_db_source": str(selected_source or ""),
        "trivy_updated_at": str(prov_trivy.get("timestamp_utc") or ""),
    }


def _db_status_probe(base: Path, tool: str) -> dict[str, Any] | None:
    """Read a scan-only DB freshness probe (``artifacts/db_status/<tool>.json``).

    Written by ``run-scan.sh`` from ``db-admin db-status`` on every run, even
    when no updater ran.  Lets the report show the *cached* DB state (present /
    age) instead of a bare ``unknown`` when provenance is absent.
    """
    probe = _read_json(base / "db_status" / f"{tool}.json")
    return probe if isinstance(probe, dict) else None


def _apply_db_probe(
    state: dict[str, str],
    *,
    state_key: str,
    version_key: str,
    updated_key: str,
    probe: dict[str, Any] | None,
) -> dict[str, str]:
    """Fill DB-state fields from a db-status probe, but only when real
    provenance produced nothing (``unknown``/blank). Provenance always wins."""
    if not isinstance(probe, dict):
        return state
    if str(state.get(state_key) or "unknown") not in ("", "unknown"):
        return state
    out = dict(state)
    exists = bool(probe.get("exists"))
    age = probe.get("age_hours")
    out[state_key] = "cached-present" if exists else "missing"
    if exists and not out.get(version_key):
        out[version_key] = f"cached (age {age}h)" if age is not None else "cached"
    if not out.get(updated_key):
        out[updated_key] = str(probe.get("timestamp_utc") or "")
    return out


def _db_snapshot_id(prov_grype: Any, prov_cve: Any) -> str:
    """Stable per-DB-state identifier.

    Built from whatever provenance is available: grype DB checksum (which
    is itself a sha256 of the archive) + cve-bin-tool activation timestamp
    or selected source.  Output is a 12-char hex hash so the header stays
    short and grep-able.
    """
    parts: list[str] = []
    if isinstance(prov_grype, dict):
        parts.append(str(prov_grype.get("checksum") or ""))
        meta = prov_grype.get("freshness_metadata") or {}
        if isinstance(meta, dict):
            parts.append(str(meta.get("built") or ""))
    if isinstance(prov_cve, dict):
        parts.append(str(prov_cve.get("selected_source") or ""))
        parts.append(str(prov_cve.get("timestamp_utc") or ""))
    parts = [p for p in parts if p]
    if not parts:
        return ""
    return _short_hash(*parts)


def _tool_failures(root: Path, grype: Any, trivy: Any, cve: Any) -> list[str]:
    """Return a list of scanner names whose output is suspicious.

    Findings are not execution errors. A scanner that ran successfully and
    found zero vulnerabilities must not be marked as failed.

    Hard failure signals, in order of directness:

    1. the cve-bin-tool timeout flag written by the wrapper;
    2. a scanner stage recorded as ``error`` in ``pipeline_state.json``;
    3. a per-tool report file *older than this run's extraction manifest* —
       i.e. a stale leftover from a previous run.  Exactly this combination
       (stage errored + old ``[]`` placeholder survived) once rendered as
       "0 findings, tool failures: none", masking a dead cve-bin-tool stage.
    """
    failed: list[str] = []
    if (root / "reports" / "cve-bin-tool" / "timeout.flag").exists():
        failed.append("cve-bin-tool")

    stage_tool = {
        "sbom": "syft",
        "grype": "grype",
        "trivy": "trivy",
        "cve-bin-tool": "cve-bin-tool",
    }
    state = _read_json(root / "pipeline_state.json")
    stages = state.get("stages") if isinstance(state, dict) else None
    if isinstance(stages, dict):
        for key, tool in stage_tool.items():
            info = stages.get(key)
            if isinstance(info, dict) and info.get("status") == "error":
                failed.append(f"{tool}: stage error (rc={info.get('rc', '?')})")

    manifest = root / "extracted" / "current" / "extraction_manifest.json"
    if manifest.exists():
        try:
            anchor = manifest.stat().st_mtime
            for tool, rel in (
                ("syft", "sbom/syft.json"),
                ("grype", "reports/grype/report.json"),
                ("trivy", "reports/trivy/report.json"),
                ("cve-bin-tool", "reports/cve-bin-tool/report.json"),
            ):
                report = root / rel
                # 60s slack: extract finishes before scanners start, so a
                # report legitimately written this run is always newer.
                if report.exists() and report.stat().st_mtime < anchor - 60:
                    failed.append(f"{tool}: stale report (predates this run's extraction)")
        except OSError:
            pass

    # Un-unpacked payload: the extracted tree still consists of archives, so the
    # scanners had nothing real to look at and every count is a truthful-looking
    # zero.  Caused by an extraction depth that is too small for a nested
    # delivery archive (zip -> tar.gz/.deb -> files).  Surfacing it as a failure
    # is the difference between "clean artifact" and "we never looked inside".
    extracted_root = root / "extracted" / "current"
    if extracted_root.is_dir():
        try:
            archive_suffixes = (
                ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tgz", ".txz", ".tbz2",
                ".tar", ".zip", ".rar", ".7z", ".rpm", ".deb", ".gz", ".zst",
            )
            files = [p for p in extracted_root.rglob("*") if p.is_file()]
            payload = [p for p in files if p.name != "extraction_manifest.json"]
            if payload:
                archives = [p for p in payload if p.name.lower().endswith(archive_suffixes)]
                if len(archives) == len(payload):
                    failed.append(
                        f"extraction: {len(archives)} nested archive(s) left unpacked "
                        f"(raise EXTRACT_MAX_DEPTH) — scanners saw no real files"
                    )
        except OSError:
            pass

    # De-duplicate, preserve order.
    seen: set[str] = set()
    return [item for item in failed if not (item in seen or seen.add(item))]


def _db_drift(
    root: Path, grype_state: dict[str, str], cve_state: dict[str, str], trivy_state: dict[str, str]
) -> str:
    """Return ``fresh`` | ``stale`` | ``unknown`` based on update-state hints."""
    states = {
        grype_state.get("update_grype_db", ""),
        cve_state.get("update_cve_db", ""),
        trivy_state.get("update_trivy_db", ""),
    }
    if "unknown" in states and len(states) == 1:
        return "unknown"
    if states <= {"refreshed-this-run", "reused-cached"} and states:
        if "reused-cached" in states:
            return "fresh-or-reused"
        return "refreshed-this-run"
    return ", ".join(sorted(s for s in states if s)) or "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def derive(root: str | Path) -> dict[str, dict[str, Any]]:
    """Compute the four sidecar JSONs for a ``reports_dir`` root.

    Returns a mapping ``{"summary": …, "status": …, "run_manifest": …,
    "db_snapshot": …}`` with the shapes ``reporting.build_report``
    consumes.  Always returns the keys; values default to empty / sensible
    placeholders when the input artefacts are missing.
    """
    base = Path(root).resolve()
    syft = _read_json(base / "sbom" / "syft.json")
    grype = _read_json(base / "reports" / "grype" / "report.json")
    trivy = _read_json(base / "reports" / "trivy" / "report.json")
    cve = _read_json(base / "reports" / "cve-bin-tool" / "report.json")
    extraction = _read_json(base / "extracted" / "current" / "extraction_manifest.json")
    if extraction is None:
        extraction = _read_json(base / "extraction_manifest.json")
    prov_grype = _read_json(base / "provenance" / "grype.json")
    prov_cve = _read_json(base / "provenance" / "cve-bin-tool-db.json")
    prov_trivy = _read_json(base / "provenance" / "trivy.json")

    syft_count = _component_count(syft)
    grype_count = _grype_match_count(grype)
    trivy_count = _trivy_match_count(trivy)
    cve_count = _cve_bin_tool_count(cve)
    input_sha = _input_sha256(extraction)
    input_hashes = _input_hashes(extraction)
    target_hashes = _target_hashes(base, extraction)
    grype_state = _grype_provenance_state(prov_grype)
    cve_state = _cve_provenance_state(prov_cve)
    trivy_state = _trivy_provenance_state(prov_trivy)
    # Scan-only fallback: when no updater ran (provenance absent) surface the
    # cached DB freshness probed by db-admin instead of a bare "unknown".
    grype_state = _apply_db_probe(
        grype_state,
        state_key="update_grype_db",
        version_key="grype_db_version",
        updated_key="grype_updated_at",
        probe=_db_status_probe(base, "grype"),
    )
    cve_state = _apply_db_probe(
        cve_state,
        state_key="update_cve_db",
        version_key="cve_db_version",
        updated_key="cve_updated_at",
        probe=_db_status_probe(base, "cve-bin-tool"),
    )
    trivy_state = _apply_db_probe(
        trivy_state,
        state_key="update_trivy_db",
        version_key="trivy_db_version",
        updated_key="trivy_updated_at",
        probe=_db_status_probe(base, "trivy"),
    )
    snapshot_id = _db_snapshot_id(prov_grype, prov_cve)
    if not snapshot_id:
        probe_parts = [
            str((_db_status_probe(base, t) or {}).get("timestamp_utc") or "")
            for t in ("grype", "trivy", "cve-bin-tool")
        ]
        probe_parts = [p for p in probe_parts if p]
        if probe_parts:
            snapshot_id = _short_hash(*probe_parts)
    failures = _tool_failures(base, grype, trivy, cve)
    drift = _db_drift(base, grype_state, cve_state, trivy_state)

    timestamp = datetime.now(UTC).isoformat()

    summary = {
        "generated_by": "resilient_updates.run_summary",
        "timestamp_utc": timestamp,
        "coverage": {
            "sbom_components": syft_count,
            "grype_matches": grype_count,
            "trivy_matches": trivy_count,
            "cve_bin_tool_matches": cve_count,
        },
        "estimated_grype_matches": grype_count,
        "estimated_cve_bin_tool_matches": cve_count,
        "tool_failures": failures or "none",
        "db_drift": drift,
        "policy_decision": "no-policy",
        "update_grype_db": grype_state["update_grype_db"],
        "update_trivy_db": trivy_state["update_trivy_db"],
        "update_cve_db": cve_state["update_cve_db"],
        "input_sha256": input_sha or "",
        "input_hashes": input_hashes,
        "target_hashes": target_hashes,
        "db_snapshot_id": snapshot_id,
    }
    status = {
        "generated_by": "resilient_updates.run_summary",
        "timestamp_utc": timestamp,
        "tool_failures": failures or "none",
        "db_drift": drift,
    }
    run_manifest = {
        "generated_by": "resilient_updates.run_summary",
        "timestamp_utc": timestamp,
        "input": {"sha256": input_sha or ""},
        "input_hashes": input_hashes,
        "target_hashes": target_hashes,
        "db_snapshot_id": snapshot_id,
    }
    db_snapshot = {
        "generated_by": "resilient_updates.run_summary",
        "timestamp_utc": timestamp,
        "snapshot_id": snapshot_id,
        "grype_built": grype_state["grype_built"],
        "grype_update_state": grype_state["update_grype_db"],
        "trivy_update_state": trivy_state["update_trivy_db"],
        "cve_update_state": cve_state["update_cve_db"],
        "tools": {
            "trivy": {
                "db_version": trivy_state["trivy_db_version"],
                "db_source": trivy_state["trivy_db_source"],
                "updated_at": trivy_state["trivy_updated_at"],
                "update_state": trivy_state["update_trivy_db"],
            },
            "grype": {
                "db_version": grype_state["grype_db_version"],
                "db_source": grype_state["grype_db_source"],
                "updated_at": grype_state["grype_updated_at"],
                "built_at": grype_state["grype_built"],
                "update_state": grype_state["update_grype_db"],
            },
            "cve-bin-tool": {
                "db_version": cve_state["cve_db_version"],
                "db_source": cve_state["cve_db_source"],
                "updated_at": cve_state["cve_updated_at"],
                "update_state": cve_state["update_cve_db"],
            },
        },
    }
    return {
        "summary": summary,
        "status": status,
        "run_manifest": run_manifest,
        "db_snapshot": db_snapshot,
    }


def write_to_disk(root: str | Path, *, overwrite: bool = True) -> dict[str, Path]:
    """Persist the four sidecar JSONs into ``root``.

    Returns a mapping ``name → path`` of the files written.  When
    ``overwrite=False`` an existing file is left untouched (useful when a
    real pipeline stage wrote a richer version and we shouldn't clobber).
    """
    derived = derive(root)
    base = Path(root).resolve()
    base.mkdir(parents=True, exist_ok=True)
    targets = {
        "summary": base / "summary.json",
        "status": base / "status.json",
        "run_manifest": base / "run_manifest.json",
        "db_snapshot": base / "db_snapshot.json",
    }
    written: dict[str, Path] = {}
    for key, payload in derived.items():
        path = targets[key]
        if not overwrite and path.exists():
            continue
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        written[key] = path
    return written


__all__ = ["derive", "write_to_disk"]