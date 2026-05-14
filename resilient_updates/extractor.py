from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
import gzip
import json
import shutil
import subprocess
import tarfile
import zipfile
from typing import Any


ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tar.zst",
    ".tar.xz",
    ".tar.bz2",
    ".tgz",
    ".tbz2",
    ".txz",
    ".zip",
    ".tar",
    ".rpm",
    ".deb",
    ".7z",
    ".rar",
    ".gz",
    ".zst",
)


@dataclass
class ExtractLimits:
    max_depth: int = 4
    max_files: int = 20000
    max_bytes: int = 10 * 1024 * 1024 * 1024


class ExtractionLimitError(RuntimeError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return cleaned.strip("._") or "artifact"


def _archive_kind(path: Path) -> str | None:
    name = path.name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if name.endswith(suffix):
            return suffix.lstrip(".").replace(".", "-")
    if path.is_file():
        try:
            if zipfile.is_zipfile(path):
                return "zip"
            if tarfile.is_tarfile(path):
                return "tar"
            with path.open("rb") as handle:
                header = handle.read(16)
            if header.startswith(b"\xed\xab\xee\xdb"):
                return "rpm"
            if header.startswith(b"!<arch>\n"):
                return "deb"
            if header.startswith(b"\x1f\x8b"):
                return "gz"
            if header.startswith(b"\x28\xb5\x2f\xfd"):
                return "zst"
            if header.startswith(b"7z\xbc\xaf\x27\x1c"):
                return "7z"
            if header.startswith(b"Rar!\x1a\x07"):
                return "rar"
        except OSError:
            return None
    return None


def _strip_archive_suffix(name: str) -> str:
    lowered = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return Path(name).stem


def _ensure_safe_member(target_dir: Path, member_name: str) -> Path:
    posix = PurePosixPath(member_name.replace("\\", "/"))
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"unsafe archive member path: {member_name}")
    target = (target_dir / Path(*posix.parts)).resolve()
    root = target_dir.resolve()
    if root != target and root not in target.parents:
        raise ValueError(f"archive member escapes target dir: {member_name}")
    return target


def _enforce_limits(output_root: Path, limits: ExtractLimits) -> None:
    file_count = 0
    total_size = 0
    for item in output_root.rglob("*"):
        if not item.is_file():
            continue
        file_count += 1
        total_size += item.stat().st_size
        if file_count > limits.max_files:
            raise ExtractionLimitError(f"extracted file count exceeds max_files={limits.max_files}")
        if total_size > limits.max_bytes:
            raise ExtractionLimitError(f"extracted size exceeds max_bytes={limits.max_bytes}")


def _extract_zip(path: Path, target_dir: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            target = _ensure_safe_member(target_dir, member.filename)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)


def _extract_tar(path: Path, target_dir: Path) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            target = _ensure_safe_member(target_dir, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)


def _extract_gzip(path: Path, target_dir: Path) -> None:
    output_name = _strip_archive_suffix(path.name)
    target = target_dir / _safe_name(output_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "rb") as source, target.open("wb") as destination:
        shutil.copyfileobj(source, destination)


def _run_checked(command: list[str], cwd: Path | None = None) -> None:
    try:
        subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required extractor tool is unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        raise RuntimeError(f"extractor tool failed: {' '.join(command)}: {stderr}") from exc


def _extract_external(path: Path, target_dir: Path, kind: str) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    if kind in {"7z", "rar"}:
        _run_checked(["7z", "x", "-y", f"-o{target_dir}", str(path)])
        return
    if kind == "zst":
        output = target_dir / _safe_name(_strip_archive_suffix(path.name))
        _run_checked(["zstd", "-d", "-f", "-o", str(output), str(path)])
        return
    if kind == "tar-zst":
        temp_tar = target_dir / f"{_safe_name(_strip_archive_suffix(path.name))}.tar"
        _run_checked(["zstd", "-d", "-f", "-o", str(temp_tar), str(path)])
        _extract_tar(temp_tar, target_dir)
        temp_tar.unlink(missing_ok=True)
        return
    if kind == "rpm":
        script = f"rpm2cpio {shlex_quote(str(path))} | cpio -idmu"
        _run_checked(["sh", "-c", script], cwd=target_dir)
        return
    if kind == "deb":
        _run_checked(["dpkg-deb", "-x", str(path), str(target_dir)])
        return
    raise RuntimeError(f"unsupported external archive kind: {kind}")


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _extract_one(path: Path, target_dir: Path, kind: str) -> str:
    target_dir.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        _extract_zip(path, target_dir)
    elif kind in {"tar", "tar-gz", "tgz", "tar-xz", "tar-bz2", "tbz2", "txz"}:
        _extract_tar(path, target_dir)
    elif kind == "gz":
        _extract_gzip(path, target_dir)
    elif kind in {"7z", "rar", "zst", "tar-zst", "rpm", "deb"}:
        _extract_external(path, target_dir, kind)
    else:
        raise RuntimeError(f"unsupported archive kind: {kind}")
    return str(target_dir)


def _find_archives(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if _archive_kind(root) else []
    ignored_parts = {"container_run", "artifacts", "__pycache__"}
    archives: list[Path] = []
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        if any(part.startswith("container_run_") or part in ignored_parts for part in item.parts):
            continue
        if item.name.lower().endswith(".sha256.txt"):
            continue
        if _archive_kind(item):
            archives.append(item)
    return sorted(archives)


def extract_artifacts(
    input_path: str | Path,
    output_root: str | Path,
    *,
    max_depth: int = 4,
    max_files: int = 20000,
    max_bytes: int = 10 * 1024 * 1024 * 1024,
) -> dict[str, Any]:
    source_root = Path(input_path).resolve()
    destination_root = Path(output_root).resolve()
    limits = ExtractLimits(max_depth=max_depth, max_files=max_files, max_bytes=max_bytes)
    destination_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "input": str(source_root),
        "output_root": str(destination_root),
        "started_at_utc": _now_iso(),
        "max_depth": max_depth,
        "max_files": max_files,
        "max_bytes": max_bytes,
        "items": [],
        "failures": [],
        "status": "running",
    }
    queue: list[tuple[Path, int]] = [(item, 0) for item in _find_archives(source_root)]
    seen: set[Path] = set()

    while queue:
        archive_path, depth = queue.pop(0)
        archive_path = archive_path.resolve()
        if archive_path in seen:
            continue
        seen.add(archive_path)
        kind = _archive_kind(archive_path)
        if not kind:
            continue
        rel = archive_path.name if source_root.is_file() else str(archive_path.relative_to(source_root))
        target_dir = destination_root / f"depth{depth}" / _safe_name(rel) / f"{_safe_name(_strip_archive_suffix(archive_path.name))}_extracted"
        item: dict[str, Any] = {
            "archive": str(archive_path),
            "relative_path": rel,
            "kind": kind,
            "depth": depth,
            "sha256": _sha256_file(archive_path),
            "output_dir": str(target_dir),
            "status": "pending",
        }
        try:
            _extract_one(archive_path, target_dir, kind)
            _enforce_limits(destination_root, limits)
            item["status"] = "extracted"
            if depth < max_depth:
                nested = [nested_path for nested_path in _find_archives(target_dir) if nested_path.resolve() not in seen]
                queue.extend((nested_path, depth + 1) for nested_path in nested)
        except Exception as exc:
            item["status"] = "failed"
            item["error"] = str(exc)
            manifest["failures"].append({"archive": str(archive_path), "error": str(exc)})
        manifest["items"].append(item)

    manifest["finished_at_utc"] = _now_iso()
    manifest["status"] = "pass" if not manifest["failures"] else "warn"
    manifest["extracted_count"] = sum(1 for item in manifest["items"] if item["status"] == "extracted")
    manifest_path = destination_root / "extraction_manifest.json"
    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest
