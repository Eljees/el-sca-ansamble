"""Runtime artifact catalog for the dashboard.

Uploaded files live under ``artifacts/uploads/<artifact-id>/`` together with a
small ``artifact.json`` metadata file.  The whole tree is already gitignored,
so operators can manage uploads and soft-delete markers without dirtying the
repository.
"""

from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

try:
    from datetime import UTC  # py3.11+
except ImportError:  # pragma: no cover - py3.10 fallback
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime

from .manifest import hash_input_archive

_CASE_ID_RE = re.compile(r"(CYBERSEC-\d+)", re.IGNORECASE)
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_UNKNOWN_CASE_IDS = {"", "CYBERSEC-UNKNOWN"}


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _safe_filename(name: str) -> str:
    base = Path(name or "artifact.bin").name
    cleaned = _SAFE_NAME_RE.sub("-", base).strip(".-")
    return cleaned or "artifact.bin"


def normalize_case_id(value: str | None) -> str:
    return (value or "").strip().upper()


def is_valid_case_id(value: str | None) -> bool:
    case_id = normalize_case_id(value)
    return not case_id or _CASE_ID_RE.fullmatch(case_id) is not None


def detect_case_id(*values: str | None) -> str:
    for value in values:
        text = (value or "").strip()
        if not text:
            continue
        found = _CASE_ID_RE.search(text)
        if found:
            return found.group(1).upper()
    return ""


class ArtifactCatalog:
    """Lightweight metadata catalog layered on top of runtime upload storage."""

    def __init__(self, artifacts_dir: Path | str):
        self.artifacts_dir = Path(artifacts_dir)
        self.uploads_dir = self.artifacts_dir / "uploads"
        self.catalog_dir = self.uploads_dir / "_catalog"
        self.legacy_dir = self.catalog_dir / "legacy-artifacts"
        self.deleted_runs_dir = self.catalog_dir / "deleted-runs"

    def list_artifacts(
        self,
        *,
        include_deleted: bool = False,
        legacy_runs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        hidden_runs = self.deleted_run_ids()
        if self.uploads_dir.is_dir():
            for entry in sorted(self.uploads_dir.iterdir(), key=lambda p: p.name, reverse=True):
                if not entry.is_dir() or entry.name.startswith("_"):
                    continue
                payload = self._read_uploaded_artifact(entry.name)
                if payload is None:
                    continue
                payload["runs"] = [run for run in payload.get("runs", []) if run.get("id") not in hidden_runs]
                payload["run_count"] = len(payload["runs"])
                payload["latest_run_id"] = payload["runs"][0]["id"] if payload["runs"] else ""
                if payload.get("deleted_at") and not include_deleted:
                    continue
                out.append(payload)
        for item in self._legacy_artifacts(legacy_runs or [], include_deleted=include_deleted):
            item["runs"] = [run for run in item.get("runs", []) if run.get("id") not in hidden_runs]
            item["run_count"] = len(item["runs"])
            item["latest_run_id"] = item["runs"][0]["id"] if item["runs"] else ""
            if item.get("deleted_at") and not include_deleted:
                continue
            out.append(item)
        out.sort(key=lambda item: (item.get("uploaded_at_utc") or "", item.get("id") or ""), reverse=True)
        return out

    def get_artifact(
        self,
        artifact_id: str,
        *,
        include_deleted: bool = False,
        legacy_runs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        for item in self.list_artifacts(include_deleted=include_deleted, legacy_runs=legacy_runs):
            if item.get("id") == artifact_id:
                return item
        return None

    def create_upload(
        self,
        *,
        filename: str,
        fileobj: Any,
        case_id: str | None = None,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        artifact_id = f"artifact-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        artifact_dir = self.uploads_dir / artifact_id
        artifact_dir.mkdir(parents=True, exist_ok=False)
        safe_name = _safe_filename(filename)
        dest = artifact_dir / safe_name
        with dest.open("wb") as fh:
            while chunk := fileobj.read(1024 * 1024):
                fh.write(chunk)
        hashes = hash_input_archive(dest)
        stat = dest.stat()
        resolved_case_id = normalize_case_id(case_id) or detect_case_id(filename, safe_name)
        payload = {
            "id": artifact_id,
            "kind": "uploaded",
            "original_filename": filename or safe_name,
            "stored_filename": safe_name,
            "stored_path": str(dest.resolve()),
            "display_name": (display_name or Path(filename or safe_name).stem).strip(),
            "case_id": resolved_case_id,
            "sha1": hashes.get("sha1", ""),
            "sha256": hashes.get("sha256", ""),
            "size": stat.st_size,
            "uploaded_at_utc": _now_utc(),
            "deleted_at": "",
            "runs": [],
        }
        _write_json(self._artifact_meta_path(artifact_id), payload)
        return payload

    def update_artifact(
        self,
        artifact_id: str,
        *,
        case_id: str | None = None,
        display_name: str | None = None,
        legacy_runs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        if artifact_id.startswith("legacy-"):
            current = self.get_artifact(artifact_id, include_deleted=True, legacy_runs=legacy_runs)
            if current is None:
                return None
            override = self._legacy_override(artifact_id) or {}
            if case_id is not None:
                override["case_id"] = normalize_case_id(case_id)
            if display_name is not None:
                override["display_name"] = display_name.strip()
            _write_json(self._legacy_meta_path(artifact_id), override)
            return self.get_artifact(artifact_id, include_deleted=True, legacy_runs=legacy_runs)

        payload = self._read_uploaded_artifact(artifact_id)
        if payload is None:
            return None
        if case_id is not None:
            payload["case_id"] = normalize_case_id(case_id)
        if display_name is not None:
            payload["display_name"] = display_name.strip()
        _write_json(self._artifact_meta_path(artifact_id), payload)
        return payload

    def soft_delete_artifact(
        self,
        artifact_id: str,
        *,
        legacy_runs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        deleted_at = _now_utc()
        if artifact_id.startswith("legacy-"):
            current = self.get_artifact(artifact_id, include_deleted=True, legacy_runs=legacy_runs)
            if current is None:
                return None
            override = self._legacy_override(artifact_id) or {}
            override["deleted_at"] = deleted_at
            _write_json(self._legacy_meta_path(artifact_id), override)
            return self.get_artifact(artifact_id, include_deleted=True, legacy_runs=legacy_runs)

        payload = self._read_uploaded_artifact(artifact_id)
        if payload is None:
            return None
        payload["deleted_at"] = deleted_at
        _write_json(self._artifact_meta_path(artifact_id), payload)
        return payload

    def add_run(self, artifact_id: str, *, run_id: str, run_dir: Path | str) -> None:
        if artifact_id.startswith("legacy-"):
            return
        payload = self._read_uploaded_artifact(artifact_id)
        if payload is None:
            return
        runs = [run for run in payload.get("runs", []) if run.get("id") != run_id]
        runs.insert(0, {"id": run_id, "path": str(Path(run_dir)), "added_at_utc": _now_utc()})
        payload["runs"] = runs
        _write_json(self._artifact_meta_path(artifact_id), payload)

    def hide_run(self, run_id: str) -> None:
        safe_name = _SAFE_NAME_RE.sub("-", run_id).strip(".-") or "run"
        _write_json(self.deleted_runs_dir / f"{safe_name}.json", {"run_id": run_id, "deleted_at": _now_utc()})

    def deleted_run_ids(self) -> set[str]:
        out: set[str] = set()
        if not self.deleted_runs_dir.is_dir():
            return out
        for path in self.deleted_runs_dir.glob("*.json"):
            payload = _read_json(path)
            run_id = str((payload or {}).get("run_id") or "").strip()
            if run_id:
                out.add(run_id)
        return out

    def purge_artifact(self, artifact_id: str) -> None:
        """Best-effort hard delete for transient test fixtures only."""
        shutil.rmtree(self.uploads_dir / artifact_id, ignore_errors=True)

    def _read_uploaded_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        payload = _read_json(self._artifact_meta_path(artifact_id))
        return payload if isinstance(payload, dict) else None

    def _artifact_meta_path(self, artifact_id: str) -> Path:
        return self.uploads_dir / artifact_id / "artifact.json"

    def _legacy_meta_path(self, artifact_id: str) -> Path:
        safe_name = _SAFE_NAME_RE.sub("-", artifact_id).strip(".-") or "legacy"
        return self.legacy_dir / f"{safe_name}.json"

    def _legacy_override(self, artifact_id: str) -> dict[str, Any] | None:
        payload = _read_json(self._legacy_meta_path(artifact_id))
        return payload if isinstance(payload, dict) else None

    def _legacy_artifacts(
        self,
        legacy_runs: list[dict[str, Any]],
        *,
        include_deleted: bool,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for run in legacy_runs:
            if run.get("id") == "current":
                continue
            run_id = str(run.get("id") or "").strip()
            run_path = Path(str(run.get("path") or ""))
            if not run_id or not run_path.is_dir():
                continue
            artifact_id = f"legacy-{run_id}"
            manifest = _read_json(run_path / "MANIFEST.json") or {}
            summary = _read_json(run_path / "summary.json") or {}
            checkpoint = _read_json(run_path / "checkpoint.json") or {}
            input_file = next((p for p in sorted((run_path / "input").glob("*")) if p.is_file()), None)
            target_host = ""
            target = manifest.get("target")
            if isinstance(target, dict):
                target_host = str(target.get("host") or "")
            filename = input_file.name if input_file else (Path(target_host).name if target_host else run_id)
            stored_path = (
                str(input_file.resolve()) if input_file else (target_host or str(run_path.resolve()))
            )
            default_case_id = normalize_case_id(
                str(manifest.get("case_id") or detect_case_id(filename, target_host, run_id))
            )
            uploaded_at = (
                str(checkpoint.get("updated_at_utc") or "")
                or str(manifest.get("finished_at") or "")
                or str(manifest.get("started_at") or "")
            )
            override = self._legacy_override(artifact_id) or {}
            item = {
                "id": artifact_id,
                "kind": "legacy-run",
                "original_filename": filename,
                "stored_filename": filename,
                "stored_path": stored_path,
                "display_name": (str(override.get("display_name") or Path(filename).stem or run_id)).strip(),
                "case_id": normalize_case_id(str(override.get("case_id") or default_case_id)),
                "sha1": "",
                "sha256": str(
                    (target.get("sha256") if isinstance(target, dict) else "")
                    or summary.get("input_sha256")
                    or ""
                ),
                "size": input_file.stat().st_size if input_file and input_file.exists() else 0,
                "uploaded_at_utc": uploaded_at,
                "deleted_at": str(override.get("deleted_at") or ""),
                "runs": [{"id": run_id, "path": str(run_path.resolve()), "added_at_utc": uploaded_at}],
            }
            if item["deleted_at"] and not include_deleted:
                continue
            out.append(item)
        return out
