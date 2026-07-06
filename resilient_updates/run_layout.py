"""Per-run artifact layout and checkpoint helpers.

The live pipeline still writes to ``artifacts/`` because compose services share
that mount.  This module creates a stable per-run directory and snapshots the
evidence files into it so reports do not disappear when the next scan starts.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

try:
    from datetime import UTC  # py3.11+
except ImportError:  # pragma: no cover - py3.10 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime

from .manifest import derive_manifest, write_manifest

_SAFE_NAME_RE = re.compile(r"[^\w._-]+", re.UNICODE)
_DEFAULT_COPY_DIRS = (
    "sbom",
    "reports/grype",
    "reports/trivy",
    "reports/cve-bin-tool",
    "reports/osv-scanner",
    "reports/final",
    "provenance",
)
_ROOT_FILES = (
    "MANIFEST.json",
    "summary.json",
    "status.json",
    "run_manifest.json",
    "db_snapshot.json",
    "run-scan.log",
    "route-plan.json",
    "route-plan.env",
)


def utc_timestamp(ts: float | None = None) -> str:
    """Return a filesystem-safe UTC timestamp."""
    value = datetime.fromtimestamp(time.time() if ts is None else ts, tz=UTC)
    return value.strftime("%Y%m%d-%H%M%S")


def slugify(value: str | None, *, fallback: str = "scan") -> str:
    """Make a short path component from a case id, project name, or filename."""
    raw = (value or "").strip()
    if not raw:
        return fallback
    raw = _SAFE_NAME_RE.sub("-", raw).strip(".-_")
    return (raw or fallback)[:80]


def project_name_from_target(target_host: str | None, case_id: str | None = None) -> str:
    """Prefer an explicit case id, otherwise derive a project-ish name from target."""
    if case_id and case_id != "CYBERSEC-UNKNOWN":
        return slugify(case_id, fallback="scan")
    if not target_host:
        return "scan"
    p = Path(target_host)
    name = p.stem if p.suffix else p.name
    return slugify(name, fallback="scan")


def run_dir_name(project_name: str, *, ts: float | None = None) -> str:
    return f"{slugify(project_name)}-{utc_timestamp(ts)}"


def resolve_run_dir(
    *,
    artifacts_dir: str | Path = "artifacts",
    target_host: str | None = None,
    case_id: str | None = None,
    mode: str = "host",
    timestamp: float | None = None,
) -> Path:
    """Return the desired per-run directory.

    ``mode``:
    - ``host``: ``<repo>/_SCA_reports/<project>-<timestamp>``
    - ``artifacts``: ``<artifacts_dir>/runs/<project>-<timestamp>``
    - ``near-source``: sibling directory next to the scanned source path
    - ``auto``: try ``near-source`` when target exists, otherwise ``artifacts``
    """
    artifacts_root = Path(artifacts_dir)
    project = project_name_from_target(target_host, case_id)
    name = run_dir_name(project, ts=timestamp)
    chosen = (mode or "host").strip().lower()
    if chosen not in {"host", "artifacts", "near-source", "auto"}:
        chosen = "host"

    if chosen == "host":
        return artifacts_root.parent / "_SCA_reports" / name

    if chosen in {"near-source", "auto"} and target_host:
        target = Path(target_host)
        if target.exists():
            return target.parent / name
        if chosen == "near-source":
            return target.parent / name

    return artifacts_root / "runs" / name


def _copy_file(src: Path, dst: Path) -> None:
    if not src.is_file():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _copy_tree(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)


def snapshot_artifacts(
    artifacts_dir: str | Path,
    run_dir: str | Path,
    *,
    case_id: str | None = None,
    target_host: str | None = None,
    target_container: str | None = None,
    include_extracted_tree: bool = False,
    stage: str | None = None,
    status: str = "snapshot",
) -> dict[str, Any]:
    """Copy current evidence from ``artifacts_dir`` into ``run_dir``.

    The default avoids copying the full extracted tree, which can be hundreds of
    megabytes.  It still copies extraction manifests and all report inputs.
    """
    src_root = Path(artifacts_dir)
    dst_root = Path(run_dir)
    dst_root.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for rel in _DEFAULT_COPY_DIRS:
        src = src_root / rel
        if src.exists():
            _copy_tree(src, dst_root / rel)
            copied.append(rel)
    for rel in _ROOT_FILES:
        src = src_root / rel
        if src.exists():
            _copy_file(src, dst_root / rel)
            copied.append(rel)

    # Preserve extraction evidence without duplicating the whole unpacked tree.
    for rel in (
        "extracted/current/extraction_manifest.json",
        "extracted/.staging/extraction_manifest.json",
    ):
        src = src_root / rel
        if src.exists():
            _copy_file(src, dst_root / rel)
            copied.append(rel)

    if include_extracted_tree and (src_root / "extracted" / "current").is_dir():
        _copy_tree(src_root / "extracted" / "current", dst_root / "extracted" / "current")
        copied.append("extracted/current")

    manifest = derive_manifest(
        dst_root,
        case_id=case_id,
        target_host=target_host,
        target_container=target_container,
    )
    write_manifest(manifest, dst_root / "MANIFEST.json")
    checkpoint = write_checkpoint(
        dst_root,
        stage=stage,
        status=status,
        artifacts_dir=src_root,
        copied=copied,
        run_id=str(manifest.get("run_id") or ""),
    )
    return {"run_dir": str(dst_root), "manifest": manifest, "checkpoint": checkpoint, "copied": copied}


def write_checkpoint(
    run_dir: str | Path,
    *,
    stage: str | None,
    status: str,
    artifacts_dir: str | Path,
    copied: list[str] | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "run_id": run_id,
        "stage": stage or "unknown",
        "status": status,
        "updated_at_utc": datetime.now(UTC).isoformat(),
        "live_artifacts_dir": str(Path(artifacts_dir)),
        "copied": sorted(set(copied or [])),
    }
    path = Path(run_dir) / "checkpoint.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return payload


def archive_current_run(
    *,
    artifacts_dir: str | Path = "artifacts",
    target_host: str | None = None,
    target_container: str | None = None,
    case_id: str | None = None,
    mode: str = "host",
    include_extracted_tree: bool = False,
    stage: str | None = "archive",
    status: str = "archived",
) -> dict[str, Any]:
    run_dir = resolve_run_dir(
        artifacts_dir=artifacts_dir,
        target_host=target_host,
        case_id=case_id,
        mode=mode,
    )
    return snapshot_artifacts(
        artifacts_dir,
        run_dir,
        case_id=case_id,
        target_host=target_host,
        target_container=target_container,
        include_extracted_tree=include_extracted_tree,
        stage=stage,
        status=status,
    )
