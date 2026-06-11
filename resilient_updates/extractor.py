from __future__ import annotations

import contextlib
import gzip
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ._io import sha256_file as _sha256_file

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
    # Optional member-level pre-filter.  Both are ``None`` by default to keep
    # the legacy "extract everything" behaviour; the CLI / Python caller
    # populates them when the operator wants to drop oversize blobs (e.g. big
    # docs/PDFs/font packs) before they ever land on the slow NTFS path.
    max_member_size_bytes: int | None = None
    skip_extensions: tuple[str, ...] | None = None


@dataclass
class ExtractionStats:
    """Mutable per-run counters; folded into the manifest at the end."""

    skipped_by_extension: int = 0
    skipped_by_size: int = 0
    errored_members: int = 0
    skipped_examples: list[dict[str, Any]] = field(default_factory=list)
    unsafe_members: list[dict[str, Any]] = field(default_factory=list)
    files_written: int = 0
    bytes_written: int = 0

    def note_skipped(self, member: str, reason: str, size: int | None) -> None:
        # Keep the manifest small but useful: log first 20 skipped paths only.
        if len(self.skipped_examples) < 20:
            self.skipped_examples.append({"member": member, "reason": reason, "size": size})

    def note_member_error(self, member: str, reason: str, size: int | None) -> None:
        # A single unreadable/corrupt member is skipped, not fatal to the archive.
        self.errored_members += 1
        if len(self.skipped_examples) < 20:
            self.skipped_examples.append({"member": member, "reason": reason, "size": size})

    def note_unsafe_member(self, member: str, reason: str, size: int | None) -> None:
        # Security-relevant (zip-slip / absolute path / escape attempts): still
        # skipped per-member, but ALSO surfaced as a manifest failure so the
        # run is marked ``warn`` — a traversal attempt must never look "pass".
        self.errored_members += 1
        if len(self.unsafe_members) < 20:
            self.unsafe_members.append({"member": member, "reason": reason, "size": size})


class ExtractionLimitError(RuntimeError):
    pass


def _note_written_file(path: Path, limits: ExtractLimits, stats: ExtractionStats) -> None:
    size = path.stat().st_size
    stats.files_written += 1
    stats.bytes_written += size
    if stats.files_written > limits.max_files:
        raise ExtractionLimitError(f"extracted file count exceeds max_files={limits.max_files}")
    if stats.bytes_written > limits.max_bytes:
        raise ExtractionLimitError(f"extracted size exceeds max_bytes={limits.max_bytes}")


def _scan_tree_usage(root: Path) -> tuple[int, int]:
    file_count = 0
    total_size = 0
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        file_count += 1
        total_size += item.stat().st_size
    return file_count, total_size


def _recount_tree_usage(root: Path, limits: ExtractLimits, stats: ExtractionStats) -> None:
    stats.files_written, stats.bytes_written = _scan_tree_usage(root)
    if stats.files_written > limits.max_files:
        raise ExtractionLimitError(f"extracted file count exceeds max_files={limits.max_files}")
    if stats.bytes_written > limits.max_bytes:
        raise ExtractionLimitError(f"extracted size exceeds max_bytes={limits.max_bytes}")


def _should_skip_member(
    member_name: str,
    member_size: int | None,
    limits: ExtractLimits,
    stats: ExtractionStats,
) -> bool:
    if limits.skip_extensions:
        lower = member_name.lower()
        for ext in limits.skip_extensions:
            if lower.endswith(ext):
                stats.note_skipped(member_name, f"extension {ext}", member_size)
                stats.skipped_by_extension += 1
                return True
    if (
        limits.max_member_size_bytes is not None
        and member_size is not None
        and member_size > limits.max_member_size_bytes
    ):
        stats.note_skipped(member_name, f"size>{limits.max_member_size_bytes}", member_size)
        stats.skipped_by_size += 1
        return True
    return False


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return cleaned.strip("._") or "artifact"


def _sanitize_component(part: str) -> str:
    """Normalize a single archive path component for cross-platform safety.

    Windows silently strips trailing dots and spaces from path components, so an
    archive member like ``app./lib`` collapses to ``app/lib`` there but creates a
    literal ``app.`` directory on Linux — producing duplicate ``app/`` and
    ``app.`` trees when the same archive is unpacked in a Linux container.  We
    normalize eagerly so extraction is deterministic regardless of host OS.
    Called only after the ``..``/absolute-path checks in ``_ensure_safe_member``,
    so it can never reintroduce a traversal component.
    """
    cleaned = part.rstrip(" .")
    return cleaned or "_"


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
        except Exception:
            # is_zipfile/is_tarfile can raise on malformed inputs (not just
            # OSError); a file we can't sniff is simply "not an archive".
            return None
    return None


def _strip_archive_suffix(name: str) -> str:
    lowered = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return Path(name).stem


def _ensure_safe_member(target_dir: Path, member_name: str, _root: Path | None = None) -> Path:
    """Return the safe absolute extraction path for *member_name* inside *target_dir*.

    Uses ``os.path.normpath`` instead of ``Path.resolve`` so that no filesystem
    I/O is performed.  ``resolve`` follows symlinks and checks that every path
    component exists — on Windows Docker Desktop that means a round-trip through
    the WSL2/virtio bind mount for *every archive member*, which hangs on large
    archives.  ``normpath`` is a pure in-memory string operation.

    Pass a pre-computed *_root* (``Path(os.path.normpath(target_dir))``) when
    iterating over many members to avoid recomputing it on every call.
    """
    posix = PurePosixPath(member_name.replace("\\", "/"))
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"unsafe archive member path: {member_name}")
    if not posix.parts:
        raise ValueError(f"archive member has empty name: {member_name!r}")
    # Normalize each component (strip trailing dots/spaces) so trailing-dot
    # directories like ``app.`` do not diverge from ``app`` on Linux hosts.
    safe_parts = tuple(_sanitize_component(part) for part in posix.parts)
    target = Path(os.path.normpath(target_dir / Path(*safe_parts)))
    root = _root if _root is not None else Path(os.path.normpath(target_dir))
    if root != target and root not in target.parents:
        raise ValueError(f"archive member escapes target dir: {member_name}")
    return target


def _extract_zip(
    path: Path,
    target_dir: Path,
    limits: ExtractLimits | None = None,
    stats: ExtractionStats | None = None,
) -> None:
    # Pre-compute _root once — avoids normpath() call per member inside the loop.
    _root = Path(os.path.normpath(target_dir))
    limits = limits or ExtractLimits()
    stats = stats or ExtractionStats()
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            # Per-member isolation: an unsafe path, encrypted/corrupt member,
            # or unsupported compression method skips just that member and is
            # recorded — it never aborts the whole archive.
            try:
                target = _ensure_safe_member(target_dir, member.filename, _root)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if _should_skip_member(member.filename, member.file_size, limits, stats):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                _note_written_file(target, limits, stats)
            except ValueError as exc:
                stats.note_unsafe_member(
                    member.filename, f"zip member: {exc}", getattr(member, "file_size", None)
                )
                continue
            except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                stats.note_member_error(
                    member.filename, f"zip member: {exc}", getattr(member, "file_size", None)
                )
                continue


def _extract_tar(
    path: Path,
    target_dir: Path,
    limits: ExtractLimits | None = None,
    stats: ExtractionStats | None = None,
) -> None:
    # Pre-compute _root once — avoids normpath() call per member inside the loop.
    _root = Path(os.path.normpath(target_dir))
    limits = limits or ExtractLimits()
    stats = stats or ExtractionStats()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            # Per-member isolation: a corrupt/unsafe entry skips just that
            # member (recorded) instead of aborting the whole archive.
            try:
                # Many tar producers include a synthetic root directory entry "."
                # before the real members. Treat it as a harmless no-op instead of
                # rejecting the whole archive as "empty name".
                raw_name = member.name.replace("\\", "/").strip("/")
                if raw_name in {"", "."} and member.isdir():
                    target_dir.mkdir(parents=True, exist_ok=True)
                    continue
                target = _ensure_safe_member(target_dir, member.name, _root)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                if _should_skip_member(member.name, member.size, limits, stats):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    continue
                with source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                _note_written_file(target, limits, stats)
            except ValueError as exc:
                stats.note_unsafe_member(member.name, f"tar member: {exc}", getattr(member, "size", None))
                continue
            except (OSError, RuntimeError, tarfile.TarError) as exc:
                stats.note_member_error(member.name, f"tar member: {exc}", getattr(member, "size", None))
                continue


def _extract_gzip(path: Path, target_dir: Path) -> None:
    output_name = _strip_archive_suffix(path.name)
    target = target_dir / _safe_name(output_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "rb") as source, target.open("wb") as destination:
        shutil.copyfileobj(source, destination)


def _run_checked(command: list[str], cwd: Path | None = None, timeout: int = 1800) -> None:
    try:
        subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required extractor tool is unavailable: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        # A corrupt/hostile 7z/rar/zst can otherwise hang the extractor forever.
        raise RuntimeError(f"extractor tool timed out after {timeout}s: {' '.join(command)}") from exc
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
        # External path bypasses the pre-filter — file size of the *.tar.zst
        # has already been decompressed, member-level skipping here would
        # only save downstream disk I/O.  Skip filter intentionally omitted
        # to keep the external path simple; if needed, run the regular tar
        # path on the decompressed file instead.
        _extract_tar(temp_tar, target_dir)
        temp_tar.unlink(missing_ok=True)
        return
    if kind == "rpm":
        # shlex.quote() handles the surprising cases (newlines, embedded
        # quotes, unicode) that the previous custom implementation missed.
        # See docs/audit/10-defects.md §11.
        from shlex import quote as _shquote

        script = f"rpm2cpio {_shquote(str(path))} | cpio -idmu"
        _run_checked(["sh", "-c", script], cwd=target_dir)
        return
    if kind == "deb":
        _run_checked(["dpkg-deb", "-x", str(path), str(target_dir)])
        return
    raise RuntimeError(f"unsupported external archive kind: {kind}")


def _extract_one(
    path: Path,
    target_dir: Path,
    kind: str,
    output_root: Path,
    limits: ExtractLimits | None = None,
    stats: ExtractionStats | None = None,
) -> str:
    limits = limits or ExtractLimits()
    stats = stats or ExtractionStats()
    target_dir.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        _extract_zip(path, target_dir, limits=limits, stats=stats)
    elif kind in {"tar", "tar-gz", "tgz", "tar-xz", "tar-bz2", "tbz2", "txz"}:
        _extract_tar(path, target_dir, limits=limits, stats=stats)
    elif kind == "gz":
        _extract_gzip(path, target_dir)
        _note_written_file(target_dir / _safe_name(_strip_archive_suffix(path.name)), limits, stats)
    elif kind in {"7z", "rar", "zst", "tar-zst", "rpm", "deb"}:
        # External tools (7z/zstd/rpm2cpio/dpkg-deb) extract the full archive
        # in one shot; per-member skipping isn't wired through here yet.
        _extract_external(path, target_dir, kind)
        _recount_tree_usage(output_root, limits, stats)
    else:
        raise RuntimeError(f"unsupported archive kind: {kind}")
    return str(target_dir)


def _find_archives(root: Path, *, ignore_generated_dirs: bool = True) -> list[Path]:
    if root.is_file():
        return [root] if _archive_kind(root) else []
    ignored_parts = {"container_run", "__pycache__"}
    if ignore_generated_dirs:
        ignored_parts.add("artifacts")
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
    max_member_size_bytes: int | None = None,
    skip_extensions: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    source_root = Path(input_path).resolve()
    destination_root = Path(output_root).resolve()
    skip_ext_tuple: tuple[str, ...] | None
    if skip_extensions:
        # Normalise: store lowercase, with leading dot, deduplicated.
        normalised: set[str] = set()
        for raw in skip_extensions:
            if not raw:
                continue
            lowered = raw.strip().lower()
            if not lowered.startswith("."):
                lowered = "." + lowered
            normalised.add(lowered)
        skip_ext_tuple = tuple(sorted(normalised)) or None
    else:
        skip_ext_tuple = None
    limits = ExtractLimits(
        max_depth=max_depth,
        max_files=max_files,
        max_bytes=max_bytes,
        max_member_size_bytes=max_member_size_bytes,
        skip_extensions=skip_ext_tuple,
    )
    stats = ExtractionStats()
    # Purge any previous run's extraction so scanning a different target cannot
    # inherit stale files from `current/` (the scanners walk the whole output
    # tree → cross-target contamination of counts otherwise). The extractor runs
    # as root in-container, so it can remove root-owned files the host cannot.
    if destination_root.exists():
        for child in destination_root.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                with contextlib.suppress(OSError):
                    child.unlink()
    destination_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "input": str(source_root),
        "output_root": str(destination_root),
        "started_at_utc": _now_iso(),
        "max_depth": max_depth,
        "max_files": max_files,
        "max_bytes": max_bytes,
        "max_member_size_bytes": max_member_size_bytes,
        "skip_extensions": list(skip_ext_tuple) if skip_ext_tuple else [],
        "items": [],
        "failures": [],
        "status": "running",
    }
    queue: list[tuple[Path, int]] = [(item, 0) for item in _find_archives(source_root)]
    seen: set[Path] = set()
    processed_archives = 0

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
        target_dir = (
            destination_root
            / f"depth{depth}"
            / _safe_name(rel)
            / f"{_safe_name(_strip_archive_suffix(archive_path.name))}_extracted"
        )
        # Guard the hash: a vanished/locked file must not abort the whole run
        # (this is computed before the try/except that wraps extraction).
        try:
            archive_sha = _sha256_file(archive_path)
        except OSError as exc:
            archive_sha = None
            manifest["failures"].append({"archive": str(archive_path), "error": f"sha256 failed: {exc}"})
        item: dict[str, Any] = {
            "archive": str(archive_path),
            "relative_path": rel,
            "kind": kind,
            "depth": depth,
            "sha256": archive_sha,
            "output_dir": str(target_dir),
            "status": "pending",
        }
        try:
            _extract_one(
                archive_path,
                target_dir,
                kind,
                destination_root,
                limits=limits,
                stats=stats,
            )
            item["status"] = "extracted"
            if depth < max_depth:
                nested = [
                    nested_path
                    for nested_path in _find_archives(target_dir, ignore_generated_dirs=False)
                    if nested_path.resolve() not in seen
                ]
                queue.extend((nested_path, depth + 1) for nested_path in nested)
        except Exception as exc:
            item["status"] = "failed"
            item["error"] = str(exc)
            manifest["failures"].append({"archive": str(archive_path), "error": str(exc)})
        manifest["items"].append(item)
        processed_archives += 1
        if processed_archives == 1 or processed_archives % 100 == 0:
            print(
                f"[extract] processed={processed_archives} queue={len(queue)} "
                f"files={stats.files_written} bytes={stats.bytes_written}",
                flush=True,
            )

    extracted_count = sum(1 for item in manifest["items"] if item["status"] == "extracted")
    for unsafe in stats.unsafe_members:
        manifest["failures"].append({"member": unsafe["member"], "error": unsafe["reason"]})
    if source_root.is_file() and extracted_count == 0 and not manifest["failures"]:
        manifest["failures"].append(
            {
                "archive": str(source_root),
                "error": "input is a file but no supported archive entries were extracted",
            }
        )

    manifest["finished_at_utc"] = _now_iso()
    manifest["status"] = "pass" if not manifest["failures"] else "warn"
    manifest["extracted_count"] = extracted_count
    manifest["pre_filter"] = {
        "skipped_by_extension": stats.skipped_by_extension,
        "skipped_by_size": stats.skipped_by_size,
        "errored_members": stats.errored_members,
        "examples": stats.skipped_examples,
    }
    manifest_path = destination_root / "extraction_manifest.json"
    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest
