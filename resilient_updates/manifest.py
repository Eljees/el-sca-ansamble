"""Build a single MANIFEST.json that ties together the artefacts of one run.

Provenance for one scan is currently scattered across six-to-eight files:

    artifacts/extraction_manifest.json
    artifacts/summary.json
    artifacts/status.json
    artifacts/db_snapshot.json
    artifacts/run_manifest.json   (only tools / timestamps today)
    artifacts/provenance/*.json
    artifacts/reports/cve-bin-tool/attempts/*.json

This module produces a single root file ``artifacts/MANIFEST.json``
referencing all of them by relative path, so a future viewer (or the
``scanner-diff`` command) can rehydrate a single run from one entry
point.  See docs/audit/20-architecture.md section 4.

The function never raises on missing files - it simply omits the
corresponding entry.  Best-effort by design, matching how
``run_summary.derive`` behaves.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._io import hash_pair, read_json, short_hash


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _existing(root: Path, *relative: str) -> list[str]:
    """Return the relative paths that actually exist on disk."""
    out: list[str] = []
    for rel in relative:
        if (root / rel).exists():
            out.append(rel)
    return out


def _glob_relpaths(root: Path, pattern: str) -> list[str]:
    """Glob inside root and return *sorted* relative paths."""
    try:
        matches = sorted((p for p in (root).rglob(pattern) if p.is_file()), key=lambda p: str(p))
        return [str(p.relative_to(root)).replace("\\", "/") for p in matches]
    except OSError:
        return []


def derive_manifest(
    artifacts_root: str | Path,
    *,
    case_id: str | None = None,
    target_host: str | None = None,
    target_container: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Compute the MANIFEST.json payload from existing artefacts."""
    root = Path(artifacts_root)

    summary = read_json(root / "summary.json") or {}
    status = read_json(root / "status.json") or {}
    db_snapshot = read_json(root / "db_snapshot.json") or {}
    extraction = read_json(root / "extraction_manifest.json") or {}
    legacy_run_manifest = read_json(root / "run_manifest.json") or {}

    started_at = legacy_run_manifest.get("started_at_utc") or extraction.get("started_at_utc") or _now()
    finished_at = legacy_run_manifest.get("finished_at_utc") or extraction.get("finished_at_utc") or _now()
    if run_id is None:
        run_id = short_hash(
            str(target_host or ""),
            str(target_container or ""),
            str(case_id or ""),
            started_at,
        )

    # Best-effort input hash.  If the extractor wrote sha256 in
    # extraction_manifest.json we keep that; otherwise leave the field
    # blank rather than re-hashing potentially large binaries.
    target_block: dict[str, Any] = {}
    if target_host:
        target_block["host"] = target_host
    if target_container:
        target_block["container"] = target_container
    input_sha = extraction.get("input_sha256") or summary.get("input_archive_sha256")
    if input_sha:
        target_block["sha256"] = input_sha

    tools: dict[str, str] = {}
    if isinstance(status.get("tools"), dict):
        for k, v in status["tools"].items():
            if isinstance(v, dict) and v.get("version"):
                tools[k] = str(v["version"])
            elif isinstance(v, str):
                tools[k] = v
    # Fallback to db_snapshot if available
    if not tools and isinstance(db_snapshot.get("tools"), dict):
        for k, v in db_snapshot["tools"].items():
            tools[k] = str(v) if not isinstance(v, dict) else str(v.get("version", ""))

    artefacts: dict[str, Any] = {}
    if (root / "extraction_manifest.json").exists():
        artefacts["extraction"] = "extraction_manifest.json"
    sbom_files = _existing(root, "sbom/syft.json", "sbom/cyclonedx.json", "sbom/spdx.json")
    if sbom_files:
        artefacts["sbom"] = sbom_files
    report_files = _existing(
        root,
        "reports/grype/report.json",
        "reports/trivy/report.json",
        "reports/cve-bin-tool/report.json",
        "reports/osv-scanner/report.json",
    )
    if report_files:
        artefacts["reports"] = report_files
    prov_files = _glob_relpaths(root / "provenance", "*.json")
    if prov_files:
        artefacts["provenance"] = ["provenance/" + p for p in prov_files]
    for canonical, rel in [
        ("summary", "summary.json"),
        ("status", "status.json"),
        ("db_snapshot", "db_snapshot.json"),
    ]:
        if (root / rel).exists():
            artefacts[canonical] = rel
    final_md_candidates = (
        sorted((root / "reports" / "final").rglob("*.md")) if (root / "reports" / "final").exists() else []
    )
    if final_md_candidates:
        artefacts["final_markdown"] = [
            str(p.relative_to(root)).replace("\\", "/") for p in final_md_candidates
        ]

    return {
        "schema_version": 1,
        "run_id": run_id,
        "case_id": case_id or "CYBERSEC-UNKNOWN",
        "started_at": started_at,
        "finished_at": finished_at,
        "target": target_block or None,
        "tools": tools,
        "artefacts": artefacts,
    }


def write_manifest(
    payload: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Write the manifest payload to ``output_path`` as pretty JSON."""
    import json

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return path


def hash_input_archive(path: Path) -> dict[str, str]:
    """Return ``{'sha1', 'sha256'}`` of an input archive in one pass."""
    return hash_pair(path)
