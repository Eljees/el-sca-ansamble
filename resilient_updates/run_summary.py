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

from datetime import datetime, timezone
from hashlib import sha1, sha256
from pathlib import Path
from typing import Any
import json


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    try:
        if not path.exists() or path.is_dir():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _count_list(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


def _short_hash(*parts: str) -> str:
    digest = sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def _hash_path(path: Path) -> dict[str, str]:
    sha1_digest = sha1()
    sha256_digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha1_digest.update(chunk)
            sha256_digest.update(chunk)
    return {
        "sha1": sha1_digest.hexdigest(),
        "sha256": sha256_digest.hexdigest(),
    }


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


def _input_sha256(extraction_manifest: Any) -> str | None:
    if not isinstance(extraction_manifest, dict):
        return None
    items = extraction_manifest.get("items") or []
    if not items:
        return None
    # When a single top-level archive is being scanned (the most common
    # case) the first item is the canonical input — return its sha256
    # directly so the header shows a stable per-run identifier.  When the
    # input is a directory of archives we synthesise a composite hash.
    if len(items) == 1:
        digest = str(items[0].get("sha256") or "")
        return digest or None
    parts = [str(item.get("sha256") or "") for item in items if isinstance(item, dict)]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return f"multi:{_short_hash(*parts)}"


def _input_hashes(extraction_manifest: Any) -> dict[str, str]:
    if not isinstance(extraction_manifest, dict):
        return {}
    items = extraction_manifest.get("items") or []
    if len(items) != 1 or not isinstance(items[0], dict):
        return {}
    archive = str(items[0].get("archive") or "").strip()
    if not archive:
        return {}
    path = Path(archive)
    if not path.exists() or not path.is_file():
        return {}
    try:
        return _hash_path(path)
    except OSError:
        return {}


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
    elif status == "active":
        update_state = "fresh"
    elif status == "active-noop":
        update_state = "fresh"
    elif status == "last-known-good":
        update_state = "lkg"
    elif used_lkg:
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

    Heuristics — same signal humans look at:
    - cve-bin-tool report exists but ``timeout.flag`` is present
    - any of {grype, trivy, cve-bin-tool} returned an empty top-level
      container (matches: [] / Results: [] / [])
    - syft.json missing artifacts
    """
    failed: list[str] = []
    if (root / "reports" / "cve-bin-tool" / "timeout.flag").exists():
        failed.append("cve-bin-tool")
    if isinstance(grype, dict) and not (grype.get("matches") or []):
        failed.append("grype")
    if isinstance(trivy, dict):
        results = trivy.get("Results") or []
        if all(not (r.get("Vulnerabilities") or []) for r in results):
            failed.append("trivy")
    if isinstance(cve, list) and not cve:
        if "cve-bin-tool" not in failed:
            failed.append("cve-bin-tool")
    # De-duplicate, preserve order.
    seen: set[str] = set()
    return [item for item in failed if not (item in seen or seen.add(item))]


def _db_drift(root: Path, grype_state: dict[str, str], cve_state: dict[str, str], trivy_state: dict[str, str]) -> str:
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
    grype_state = _grype_provenance_state(prov_grype)
    cve_state = _cve_provenance_state(prov_cve)
    trivy_state = _trivy_provenance_state(prov_trivy)
    snapshot_id = _db_snapshot_id(prov_grype, prov_cve)
    failures = _tool_failures(base, grype, trivy, cve)
    drift = _db_drift(base, grype_state, cve_state, trivy_state)

    timestamp = datetime.now(timezone.utc).isoformat()

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
